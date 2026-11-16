package sshconfig

import (
	"context"
	"errors"
	"strings"
	"testing"

	"app/internal/karte"
	"app/internal/remote"
)

// Ubuntu 20.04 で、パスワードログインを許可したままの patient01 を想定した sshd -T の出力（抜粋）。
// 実機で取った出力に差し替えると、より確かなテストになる。
const effHoles = `port 22
addressfamily any
usepam yes
permitrootlogin without-password
pubkeyauthentication yes
passwordauthentication yes
permitemptypasswords no
kbdinteractiveauthentication no
challengeresponseauthentication no
hostkey /etc/ssh/ssh_host_rsa_key
hostkey /etc/ssh/ssh_host_ed25519_key
`

const whereHoles = `/etc/ssh/sshd_config:58:PasswordAuthentication yes
/etc/ssh/sshd_config:63:ChallengeResponseAuthentication no
/etc/ssh/sshd_config.d/50-cloud-init.conf:1:PasswordAuthentication yes
`

const effClean = `usepam yes
permitrootlogin without-password
pubkeyauthentication yes
passwordauthentication no
permitemptypasswords no
kbdinteractiveauthentication no
`

func codes(res karte.CheckResult) []string {
	var cs []string
	for _, f := range res.Findings {
		cs = append(cs, f.Code)
	}
	return cs
}

func TestParseEffective(t *testing.T) {
	m := ParseEffective(effHoles)
	if m["passwordauthentication"] != "yes" || m["usepam"] != "yes" {
		t.Fatalf("%+v", m)
	}
	if m["hostkey"] != "/etc/ssh/ssh_host_rsa_key" {
		t.Errorf("複数行の項目は最初の値を残す: %q", m["hostkey"])
	}
}

func TestParseWhere(t *testing.T) {
	locs := ParseWhere(whereHoles)
	if len(locs) != 3 {
		t.Fatalf("3件のはず: %+v", locs)
	}
	l := locs[2]
	if l.File != "/etc/ssh/sshd_config.d/50-cloud-init.conf" || l.Line != "1" || l.Key != "passwordauthentication" || l.Value != "yes" {
		t.Errorf("%+v", l)
	}
}

func TestAnalyzePasswordLogin(t *testing.T) {
	res := Analyze(ParseEffective(effHoles), ParseWhere(whereHoles))
	if res.Grade != karte.GradeC {
		t.Errorf("判定 = %s, want C", res.Grade)
	}
	if got := codes(res); len(got) != 1 || got[0] != "SSH_PASSWORD_LOGIN" {
		t.Fatalf("所見 = %v", got)
	}
	what := res.Findings[0].What
	// 本体と sshd_config.d の両方を場所として示す
	if !strings.Contains(what, "50-cloud-init.conf の 1行目") || !strings.Contains(what, "sshd_config の 58行目") {
		t.Errorf("設定の場所が説明に入っていない: %s", what)
	}
}

func TestAnalyzeKeyOnly(t *testing.T) {
	res := Analyze(ParseEffective(effClean), nil)
	if res.Grade != karte.GradeA {
		t.Errorf("判定 = %s, want A", res.Grade)
	}
	if got := codes(res); len(got) != 1 || got[0] != "SSH_KEY_ONLY" {
		t.Fatalf("所見 = %v", got)
	}
	if res.Summary != "鍵でのみログインできる設定です" {
		t.Errorf("一言 = %q", res.Summary)
	}
}

func TestAnalyzeKbdInteractive(t *testing.T) {
	// PasswordAuthentication だけ no にしても、PAM＋キーボード対話認証でパスワードが通る
	eff := ParseEffective(strings.Replace(effClean, "kbdinteractiveauthentication no", "kbdinteractiveauthentication yes", 1))
	res := Analyze(eff, nil)
	if got := codes(res); len(got) != 1 || got[0] != "SSH_KBDINTERACTIVE_LOGIN" {
		t.Fatalf("所見 = %v", got)
	}
	if !strings.Contains(res.Findings[0].What, "kbdinteractiveauthentication") {
		t.Errorf("項目名が説明に入っていない: %s", res.Findings[0].What)
	}

	// PAM を使っていなければ、パスワードは聞かれない
	eff["usepam"] = "no"
	if got := codes(Analyze(eff, nil)); got[0] != "SSH_KEY_ONLY" {
		t.Errorf("usepam no なら問題なし: %v", got)
	}
}

func TestAnalyzeOldChallengeResponse(t *testing.T) {
	// Ubuntu 20.04（OpenSSH 8.2）は古い名前で出る
	eff := map[string]string{
		"passwordauthentication":          "no",
		"challengeresponseauthentication": "yes",
		"usepam":                          "yes",
		"permitrootlogin":                 "without-password",
		"pubkeyauthentication":            "yes",
	}
	res := Analyze(eff, nil)
	if got := codes(res); len(got) != 1 || got[0] != "SSH_KBDINTERACTIVE_LOGIN" {
		t.Fatalf("所見 = %v", got)
	}
	if !strings.Contains(res.Findings[0].What, "challengeresponseauthentication") {
		t.Errorf("%s", res.Findings[0].What)
	}
}

func TestAnalyzeRootAndEmpty(t *testing.T) {
	eff := ParseEffective(effHoles)
	eff["permitrootlogin"] = "yes"
	eff["permitemptypasswords"] = "yes"
	res := Analyze(eff, nil)
	if res.Grade != karte.GradeE {
		t.Errorf("判定 = %s, want E", res.Grade)
	}
	got := codes(res)
	want := []string{"SSH_EMPTY_PASSWORD", "SSH_ROOT_PASSWORD_LOGIN", "SSH_PASSWORD_LOGIN"} // 悪い順
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("所見 = %v, want %v", got, want)
	}
	if !strings.Contains(res.Findings[0].What, "設定ファイルには書かれていません") {
		t.Errorf("場所が分からないときの説明: %s", res.Findings[0].What)
	}
}

func TestAnalyzeRootKeyOnly(t *testing.T) {
	eff := ParseEffective(effClean)
	eff["permitrootlogin"] = "yes"
	res := Analyze(eff, nil)
	if res.Grade != karte.GradeB {
		t.Errorf("判定 = %s, want B", res.Grade)
	}
	if got := codes(res); len(got) != 1 || got[0] != "SSH_ROOT_LOGIN" {
		t.Errorf("所見 = %v", got)
	}
}

func TestRun(t *testing.T) {
	r := &remote.FakeRunner{SudoOutputs: map[string]string{
		cmdEffective: effHoles,
		cmdWhere:     whereHoles,
	}}
	res, err := Run(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if res.CheckID != CheckID || res.Grade != karte.GradeC {
		t.Errorf("%+v", res)
	}
	if !strings.Contains(res.Evidence, "passwordauthentication yes") || strings.Contains(res.Evidence, "hostkey") {
		t.Errorf("根拠は関係する項目だけ: %s", res.Evidence)
	}
	for _, c := range r.Calls {
		if !strings.HasPrefix(c, "sudo ") {
			t.Errorf("sudo で実行するはず: %s", c)
		}
	}
}

func TestRunNoMatch(t *testing.T) {
	// grep で見つからない（終了コード1）でも診断は続ける
	r := &remote.FakeRunner{SudoOutputs: map[string]string{cmdEffective: effClean}}
	res, err := Run(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if res.Grade != karte.GradeA || !strings.Contains(res.Evidence, "初期値が使われています") {
		t.Errorf("%+v", res)
	}
}

type failRunner struct{ *remote.FakeRunner }

func (failRunner) RunSudo(context.Context, string) (string, error) {
	return "", errors.New("コマンドが失敗しました（終了コード 255）")
}

func TestRunSshdFails(t *testing.T) {
	res, err := Run(context.Background(), failRunner{&remote.FakeRunner{}})
	if err != nil {
		t.Fatal(err)
	}
	if got := codes(res); len(got) != 1 || got[0] != "SSH_CONFIG_UNKNOWN" || res.Grade != karte.GradeC {
		t.Errorf("%+v", res)
	}
}
