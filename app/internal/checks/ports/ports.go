// Package ports はポート診断（F05 / WBS 4.1）。
//
// 調べること
//  1. どのポートが、どこからの接続を待ち受けているか（ss -H -tulpn）
//  2. ファイアウォール（ufw）が有効か（ufw status）
//  3. Docker で公開しているポートがあるか（ufw をすり抜けるため）
//
// 実行するのは読み取りだけのコマンド（設計方針）。
package ports

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"app/internal/karte"
	"app/internal/remote"
)

const (
	CheckID   = "ports"
	CheckName = "ポート診断"

	cmdListen = "ss -H -tulpn"
	// 表示を英語にそろえて、解析しやすくする
	cmdUFW = "env LC_ALL=C ufw status"
)

// Scope は待ち受け先の範囲。
type Scope string

const (
	ScopeAll      Scope = "all"      // 0.0.0.0 / :: / * ＝ すべてのネットワークから
	ScopeLocal    Scope = "local"    // 127.0.0.1 / ::1 ＝ このサーバーの中だけ
	ScopeSpecific Scope = "specific" // 特定のアドレス（LANのIPなど）
)

// Listener は待ち受けている1つのポート。
type Listener struct {
	Proto   string // tcp / udp
	Addr    string // 待ち受け先（ss の表記のまま。例：0.0.0.0、[::]、127.0.0.53%lo）
	Port    int
	Process string // プロセス名（sudo がないと空になる）
	Scope   Scope
}

// Exposed は外部から届く可能性があるかを返す。
func (l Listener) Exposed() bool { return l.Scope != ScopeLocal }

// ParseSS は `ss -H -tulpn` の出力を解析する。
//
// 1行の例：
//
//	tcp   LISTEN 0  4096  0.0.0.0:22  0.0.0.0:*  users:(("sshd",pid=800,fd=3))
func ParseSS(out string) []Listener {
	var ls []Listener
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		proto := strings.ToLower(f[0])
		if proto != "tcp" && proto != "udp" {
			continue
		}
		state := strings.ToUpper(f[1])
		if proto == "tcp" && state != "LISTEN" {
			continue
		}
		host, port, ok := splitHostPort(f[4])
		if !ok {
			continue
		}
		process := ""
		if len(f) >= 7 {
			process = processName(strings.Join(f[6:], " "))
		}
		ls = append(ls, Listener{Proto: proto, Addr: host, Port: port, Process: process, Scope: scopeOf(host)})
	}
	return ls
}

// splitHostPort は「0.0.0.0:22」「[::]:80」「*:3000」「127.0.0.53%lo:53」を分ける。
func splitHostPort(s string) (string, int, bool) {
	i := strings.LastIndex(s, ":")
	if i <= 0 {
		return "", 0, false
	}
	port, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return "", 0, false
	}
	return s[:i], port, true
}

func scopeOf(host string) Scope {
	h := strings.Trim(host, "[]")
	if i := strings.Index(h, "%"); i >= 0 { // 127.0.0.53%lo → 127.0.0.53
		h = h[:i]
	}
	h = strings.TrimPrefix(h, "::ffff:") // IPv4射影アドレス
	switch {
	case h == "*", h == "0.0.0.0", h == "::":
		return ScopeAll
	case strings.HasPrefix(h, "127."), h == "::1", h == "localhost":
		return ScopeLocal
	default:
		return ScopeSpecific
	}
}

// processName は users:(("sshd",pid=800,fd=3)) から sshd を取り出す。
func processName(s string) string {
	start := strings.Index(s, `(("`)
	if start < 0 {
		return ""
	}
	rest := s[start+3:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// --- 判定 ---

type kind int

const (
	kindIgnore    kind = iota // 外部から届いても普通のもの（DHCPの受信など）
	kindExpected              // 外部から使うためのもの（SSH・Web）
	kindDB                    // データベースなど
	kindDockerAPI             // Docker の操作窓口
	kindPlaintext             // 暗号化しない古い仕組み
	kindDev                   // 開発用でよく使う番号
	kindUnknown               // 用途を確かめたいもの
)

type portInfo struct {
	service string
	kind    kind
}

// 番号とサービスの対応表（よく使われるものに絞る）。
var knownPorts = map[string]portInfo{
	"tcp/22":    {"SSH", kindExpected},
	"tcp/80":    {"Webサーバー（HTTP）", kindExpected},
	"tcp/443":   {"Webサーバー（HTTPS）", kindExpected},
	"udp/68":    {"DHCP（IPアドレスの受け取り）", kindIgnore},
	"udp/546":   {"DHCPv6（IPアドレスの受け取り）", kindIgnore},
	"udp/5353":  {"mDNS（同じネットワーク内の名前解決）", kindExpected},
	"tcp/3306":  {"MySQL / MariaDB", kindDB},
	"tcp/5432":  {"PostgreSQL", kindDB},
	"tcp/6379":  {"Redis", kindDB},
	"tcp/27017": {"MongoDB", kindDB},
	"tcp/9200":  {"Elasticsearch", kindDB},
	"tcp/11211": {"Memcached", kindDB},
	"udp/11211": {"Memcached", kindDB},
	"tcp/5984":  {"CouchDB", kindDB},
	"tcp/2375":  {"Docker API", kindDockerAPI},
	"tcp/21":    {"FTP", kindPlaintext},
	"tcp/23":    {"Telnet", kindPlaintext},
	"tcp/3000":  {"開発用サーバー", kindDev},
	"tcp/3001":  {"開発用サーバー", kindDev},
	"tcp/4200":  {"開発用サーバー", kindDev},
	"tcp/5000":  {"開発用サーバー", kindDev},
	"tcp/5173":  {"開発用サーバー", kindDev},
	"tcp/8000":  {"開発用サーバー", kindDev},
	"tcp/8080":  {"開発用サーバー", kindDev},
	"tcp/8081":  {"開発用サーバー", kindDev},
	"tcp/8888":  {"開発用サーバー", kindDev},
}

// プロセス名からデータベースを見分ける（番号を変えていても気づけるように）。
var dbProcesses = map[string]string{
	"mysqld":        "MySQL",
	"mariadbd":      "MariaDB",
	"postgres":      "PostgreSQL",
	"redis-server":  "Redis",
	"mongod":        "MongoDB",
	"memcached":     "Memcached",
	"elasticsearch": "Elasticsearch",
}

func classify(l Listener) portInfo {
	if name, ok := dbProcesses[l.Process]; ok {
		return portInfo{name, kindDB}
	}
	if info, ok := knownPorts[fmt.Sprintf("%s/%d", l.Proto, l.Port)]; ok {
		return info
	}
	return portInfo{"", kindUnknown}
}

// Run はポート診断を行う。
func Run(ctx context.Context, r remote.Runner) (karte.CheckResult, error) {
	ssOut, err := r.RunSudo(ctx, cmdListen)
	if err != nil {
		return karte.CheckResult{}, fmt.Errorf("待ち受けポートを調べられませんでした: %w", err)
	}
	ufwOut, ufwErr := r.RunSudo(ctx, cmdUFW)

	res := Analyze(ParseSS(ssOut), ufwOut, ufwErr == nil)
	res.Evidence = "$ sudo " + cmdListen + "\n" + strings.TrimRight(ssOut, "\n") +
		"\n\n$ sudo " + cmdUFW + "\n" + strings.TrimRight(ufwOut, "\n")
	return res, nil
}

// Analyze は解析済みの待ち受け一覧と ufw の出力から、カルテを作る。
func Analyze(listeners []Listener, ufwOut string, ufwOK bool) karte.CheckResult {
	res := karte.CheckResult{CheckID: CheckID, Name: CheckName, Grade: karte.GradeA}

	// 同じポートを IPv4 と IPv6 の両方で待ち受けていることが多いので、1つにまとめる。
	type key struct {
		proto string
		port  int
	}
	seen := map[key]bool{}
	var exposed []Listener
	for _, l := range listeners {
		if !l.Exposed() {
			continue
		}
		k := key{l.Proto, l.Port}
		if seen[k] {
			continue
		}
		seen[k] = true
		exposed = append(exposed, l)
	}
	sort.Slice(exposed, func(i, j int) bool {
		if exposed[i].Port != exposed[j].Port {
			return exposed[i].Port < exposed[j].Port
		}
		return exposed[i].Proto < exposed[j].Proto
	})

	var findings []karte.Finding
	var dockerPorts []string
	publicCount := 0
	for _, l := range exposed {
		info := classify(l)
		if info.kind == kindIgnore {
			continue
		}
		publicCount++
		if l.Process == "docker-proxy" {
			dockerPorts = append(dockerPorts, strconv.Itoa(l.Port))
		}
		process := l.Process
		if process == "" {
			process = "（不明）"
		}
		params := map[string]string{
			"port":    strconv.Itoa(l.Port),
			"proto":   l.Proto,
			"addr":    l.Addr,
			"process": process,
			"service": info.service,
		}
		code, grade := "", karte.GradeA
		switch info.kind {
		case kindDB:
			code, grade = "PORT_DB_PUBLIC", karte.GradeE
		case kindDockerAPI:
			code, grade = "PORT_DOCKER_API_PUBLIC", karte.GradeE
		case kindPlaintext:
			code, grade = "PORT_PLAINTEXT_PUBLIC", karte.GradeD
		case kindDev:
			code, grade = "PORT_DEV_PUBLIC", karte.GradeC
		case kindExpected:
			code, grade = "PORT_EXPECTED_PUBLIC", karte.GradeA
		default:
			code, grade = "PORT_UNKNOWN_PUBLIC", karte.GradeC
		}
		findings = append(findings, karte.Finding{Code: code, Grade: grade, Params: params})
	}

	// ファイアウォール
	ufwStatus := parseUFW(ufwOut)
	switch {
	case !ufwOK || ufwStatus == "":
		findings = append(findings, karte.Finding{Code: "FIREWALL_UNKNOWN", Grade: karte.GradeC, Params: map[string]string{}})
	case ufwStatus == "inactive":
		findings = append(findings, karte.Finding{Code: "FIREWALL_INACTIVE", Grade: karte.GradeC, Params: map[string]string{}})
	}

	// Docker の公開ポートは ufw をすり抜ける
	if len(dockerPorts) > 0 {
		grade := karte.GradeC
		if ufwStatus == "active" {
			grade = karte.GradeD // ufw で守っているつもりになっている可能性が高い
		}
		findings = append(findings, karte.Finding{
			Code: "DOCKER_BYPASSES_UFW", Grade: grade,
			Params: map[string]string{"ports": strings.Join(dockerPorts, "、")},
		})
	}

	if publicCount == 0 {
		findings = append(findings, karte.Finding{Code: "PORT_NONE_PUBLIC", Grade: karte.GradeA, Params: map[string]string{}})
	}

	for i := range findings {
		findings[i] = karte.Describe(findings[i])
		res.Grade = karte.Worse(res.Grade, findings[i].Grade)
	}
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].Grade > findings[j].Grade })
	res.Findings = findings

	switch {
	case publicCount == 0:
		res.Summary = "外部から届くポートはありません"
	default:
		risky := 0
		for _, f := range findings {
			if strings.HasPrefix(f.Code, "PORT_") && f.Grade != karte.GradeA {
				risky++
			}
		}
		if risky == 0 {
			res.Summary = fmt.Sprintf("外部から届くポート %d件（いずれも想定どおり）", publicCount)
		} else {
			res.Summary = fmt.Sprintf("外部から届くポート %d件（うち要確認 %d件）", publicCount, risky)
		}
	}
	return res
}

// parseUFW は `ufw status` の出力から active / inactive を返す。分からなければ空。
func parseUFW(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "Status:"); ok {
			return strings.ToLower(strings.TrimSpace(v))
		}
		// 日本語環境の表示（状態: アクティブ）にも対応する
		if v, ok := strings.CutPrefix(line, "状態:"); ok {
			v = strings.TrimSpace(v)
			if v == "アクティブ" {
				return "active"
			}
			if v == "非アクティブ" {
				return "inactive"
			}
		}
	}
	return ""
}
