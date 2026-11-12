package ports

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"app/internal/karte"
	"app/internal/remote"
)

// わざと穴を開けた patient01 を想定した ss の出力。
// 実機で取った出力に差し替えると、より確かなテストになる。
const ssHoles = `udp   UNCONN 0      0          127.0.0.53%lo:53        0.0.0.0:*    users:(("systemd-resolve",pid=600,fd=12))
udp   UNCONN 0      0      0.0.0.0%enp0s3:68           0.0.0.0:*    users:(("systemd-network",pid=580,fd=15))
tcp   LISTEN 0      4096       127.0.0.53%lo:53        0.0.0.0:*    users:(("systemd-resolve",pid=600,fd=13))
tcp   LISTEN 0      128              0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=800,fd=3))
tcp   LISTEN 0      151              0.0.0.0:3306      0.0.0.0:*    users:(("mysqld",pid=900,fd=21))
tcp   LISTEN 0      4096             0.0.0.0:8080      0.0.0.0:*    users:(("docker-proxy",pid=1200,fd=4))
tcp   LISTEN 0      511            127.0.0.1:3000      0.0.0.0:*    users:(("node",pid=1300,fd=18))
tcp   LISTEN 0      128                 [::]:22           [::]:*    users:(("sshd",pid=800,fd=4))
tcp   LISTEN 0      4096                [::]:8080         [::]:*    users:(("docker-proxy",pid=1210,fd=4))
tcp   LISTEN 0      5                      *:7777            *:*    users:(("python3",pid=1400,fd=3))
`

const ssClean = `tcp   LISTEN 0      128            127.0.0.1:5432      0.0.0.0:*    users:(("postgres",pid=900,fd=5))
tcp   LISTEN 0      128              0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=800,fd=3))
tcp   LISTEN 0      128                 [::]:22           [::]:*    users:(("sshd",pid=800,fd=4))
udp   UNCONN 0      0      0.0.0.0%enp0s3:68           0.0.0.0:*    users:(("systemd-network",pid=580,fd=15))
`

func TestParseSS(t *testing.T) {
	ls := ParseSS(ssHoles)
	if len(ls) != 10 {
		t.Fatalf("10件のはず: %d件 %+v", len(ls), ls)
	}
	want := map[string]Scope{
		"127.0.0.53%lo:53": ScopeLocal,
		"0.0.0.0:22":       ScopeAll,
		"[::]:22":          ScopeAll,
		"*:7777":           ScopeAll,
		"127.0.0.1:3000":   ScopeLocal,
	}
	for _, l := range ls {
		k := l.Addr + ":" + itoa(l.Port)
		if s, ok := want[k]; ok && s != l.Scope {
			t.Errorf("%s の範囲 = %s, want %s", k, l.Scope, s)
		}
	}
	if ls[3].Process != "sshd" {
		t.Errorf("プロセス名 = %q, want sshd", ls[3].Process)
	}
}

func TestParseSSWithoutProcess(t *testing.T) {
	// sudo なしで実行すると users:(...) が付かない
	ls := ParseSS("tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n")
	if len(ls) != 1 || ls[0].Process != "" || ls[0].Port != 22 {
		t.Fatalf("%+v", ls)
	}
}

func TestScopeOf(t *testing.T) {
	cases := map[string]Scope{
		"0.0.0.0":            ScopeAll,
		"[::]":               ScopeAll,
		"*":                  ScopeAll,
		"127.0.0.1":          ScopeLocal,
		"[::1]":              ScopeLocal,
		"[::ffff:127.0.0.1]": ScopeLocal,
		"127.0.0.53%lo":      ScopeLocal,
		"192.168.56.104":     ScopeSpecific,
		"0.0.0.0%enp0s3":     ScopeAll,
	}
	for in, want := range cases {
		if got := scopeOf(in); got != want {
			t.Errorf("scopeOf(%q) = %s, want %s", in, got, want)
		}
	}
}

func codes(res karte.CheckResult) map[string]karte.Finding {
	m := map[string]karte.Finding{}
	for _, f := range res.Findings {
		m[f.Code+":"+f.Params["port"]] = f
	}
	return m
}

func TestAnalyzeHoles(t *testing.T) {
	res := Analyze(ParseSS(ssHoles), "Status: active\n", true)
	got := codes(res)

	db, ok := got["PORT_DB_PUBLIC:3306"]
	if !ok || db.Grade != karte.GradeE {
		t.Fatalf("MySQL の外部公開は E のはず: %+v", got)
	}
	if !strings.Contains(db.Title, "MySQL") || !strings.Contains(db.Title, "3306") {
		t.Errorf("説明文に値が差し込まれていない: %q", db.Title)
	}
	if f := got["PORT_DEV_PUBLIC:8080"]; f.Grade != karte.GradeC {
		t.Errorf("8080 は開発用 C のはず: %+v", f)
	}
	if f := got["PORT_UNKNOWN_PUBLIC:7777"]; f.Grade != karte.GradeC {
		t.Errorf("7777 は要確認 C のはず: %+v", f)
	}
	if f := got["PORT_EXPECTED_PUBLIC:22"]; f.Grade != karte.GradeA {
		t.Errorf("SSH は A のはず: %+v", f)
	}
	if _, ok := got["PORT_DEV_PUBLIC:3000"]; ok {
		t.Error("127.0.0.1 の 3000 は外部から届かないので、所見にしない")
	}
	for k := range got {
		if strings.HasSuffix(k, ":68") || strings.HasSuffix(k, ":53") {
			t.Errorf("DHCP・ローカルDNS は所見にしない: %s", k)
		}
	}
	// ufw が有効でも Docker の公開ポートはすり抜ける → D
	if f := got["DOCKER_BYPASSES_UFW:"]; f.Grade != karte.GradeD || f.Params["ports"] != "8080" {
		t.Errorf("Docker のすり抜けは D・8080 のはず: %+v", f)
	}
	if res.Grade != karte.GradeE {
		t.Errorf("総合は E のはず: %s", res.Grade)
	}
	// 22・3306・7777・8080（IPv6 の重複は1つにまとめる）
	if res.Summary != "外部から届くポート 4件（うち要確認 3件）" {
		t.Errorf("Summary = %q", res.Summary)
	}
	if res.Findings[0].Grade != karte.GradeE {
		t.Errorf("悪い順に並んでいない: %+v", res.Findings[0])
	}
}

func TestAnalyzeClean(t *testing.T) {
	res := Analyze(ParseSS(ssClean), "Status: active\n", true)
	if res.Grade != karte.GradeA {
		t.Fatalf("穴なしは A のはず: %s %+v", res.Grade, res.Findings)
	}
	if res.Summary != "外部から届くポート 1件（いずれも想定どおり）" {
		t.Errorf("Summary = %q", res.Summary)
	}
}

func TestAnalyzeFirewall(t *testing.T) {
	res := Analyze(ParseSS(ssClean), "Status: inactive\n", true)
	if _, ok := codes(res)["FIREWALL_INACTIVE:"]; !ok || res.Grade != karte.GradeC {
		t.Errorf("ufw 無効は C のはず: %s %+v", res.Grade, res.Findings)
	}
	res = Analyze(ParseSS(ssClean), "sudo: ufw: command not found\n", false)
	if _, ok := codes(res)["FIREWALL_UNKNOWN:"]; !ok {
		t.Errorf("ufw が読めなければ FIREWALL_UNKNOWN のはず: %+v", res.Findings)
	}
}

func TestAnalyzeNothingPublic(t *testing.T) {
	res := Analyze(ParseSS("tcp LISTEN 0 1 127.0.0.1:5432 0.0.0.0:* users:((\"postgres\",pid=1,fd=1))\n"), "Status: active", true)
	if _, ok := codes(res)["PORT_NONE_PUBLIC:"]; !ok || res.Summary != "外部から届くポートはありません" {
		t.Errorf("%+v %q", res.Findings, res.Summary)
	}
}

func TestDBDetectedByProcessName(t *testing.T) {
	// 番号を変えていても、プロセス名で気づける
	res := Analyze(ParseSS("tcp LISTEN 0 1 0.0.0.0:13306 0.0.0.0:* users:((\"mysqld\",pid=1,fd=1))\n"), "Status: active", true)
	if f, ok := codes(res)["PORT_DB_PUBLIC:13306"]; !ok || f.Grade != karte.GradeE {
		t.Errorf("%+v", res.Findings)
	}
}

func TestRunUsesSudoReadOnlyCommands(t *testing.T) {
	r := &remote.FakeRunner{SudoOutputs: map[string]string{
		cmdListen: ssHoles,
		cmdUFW:    "Status: active\n",
	}}
	res, err := Run(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if res.Grade != karte.GradeE || !strings.Contains(res.Evidence, "$ sudo ss -H -tulpn") {
		t.Errorf("%s %q", res.Grade, res.Evidence)
	}
	if len(r.Calls) != 2 {
		t.Errorf("呼んだコマンド: %v", r.Calls)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
