// Package sshconfig はSSH設定診断（WBS 4.2）。
//
// 調べること
//  1. sshd が実際に使っている設定値（sshd -T）
//     sshd_config.d の追加ファイルや初期値も反映された「最終的な値」が分かる。
//  2. その設定がどのファイルの何行目に書かれているか（grep）
//     Ubuntu では sshd_config.d/ のファイルが本体の sshd_config より優先されるため、
//     「本体を直したのに変わらない」つまずきの手がかりにする。
//
// 実行するのは読み取りだけのコマンド（設計方針）。
package sshconfig

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"app/internal/karte"
	"app/internal/remote"
)

const (
	CheckID   = "sshconfig"
	CheckName = "SSH設定診断"

	// 実際に使われる設定値を表示する（設定を変えたり、sshd を再起動したりはしない）
	cmdEffective = "sshd -T"
	// 設定が書かれている場所を探す
	cmdWhere = `grep -rHinE '^[[:space:]]*(passwordauthentication|permitrootlogin|permitemptypasswords|kbdinteractiveauthentication|challengeresponseauthentication|pubkeyauthentication)[[:space:]]' /etc/ssh/sshd_config /etc/ssh/sshd_config.d`
)

// 判定に使う設定項目（sshd -T では小文字で出る）。根拠として画面に出すのもこれだけにする。
var watchedKeys = []string{
	"passwordauthentication",
	"kbdinteractiveauthentication",
	"challengeresponseauthentication", // OpenSSH 8.7 より前の名前（Ubuntu 20.04 など）
	"usepam",
	"permitrootlogin",
	"permitemptypasswords",
	"pubkeyauthentication",
}

// ParseEffective は `sshd -T` の出力（「項目名 値」の行の並び）を解析する。
// 同じ項目が複数行出るもの（hostkey など）は、最初の値だけを残す。
func ParseEffective(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		k := strings.ToLower(f[0])
		if _, ok := m[k]; ok {
			continue
		}
		m[k] = strings.ToLower(strings.Join(f[1:], " "))
	}
	return m
}

// Location は設定が書かれている場所（grep の1行）。
type Location struct {
	File  string
	Line  string
	Key   string // 小文字
	Value string
}

// ParseWhere は `grep -Hin` の出力（ファイル:行番号:内容）を解析する。
func ParseWhere(out string) []Location {
	var locs []Location
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		f := strings.Fields(parts[2])
		if len(f) < 2 {
			continue
		}
		locs = append(locs, Location{
			File: parts[0], Line: parts[1],
			Key: strings.ToLower(f[0]), Value: f[1],
		})
	}
	return locs
}

// Run はSSH設定診断を行う。
func Run(ctx context.Context, r remote.Runner) (karte.CheckResult, error) {
	effOut, err := r.RunSudo(ctx, cmdEffective)
	if err != nil {
		if ctx.Err() != nil {
			return karte.CheckResult{}, ctx.Err()
		}
		// sshd -T が使えない環境でも、診断全体は止めない
		res := Analyze(nil, nil)
		res.Evidence = "$ sudo " + cmdEffective + "\n（実行できませんでした：" + err.Error() + "）"
		return res, nil
	}
	// 見つからないとき grep は終了コード1を返すので、エラーは「書かれていない」として扱う
	whereOut, _ := r.RunSudo(ctx, cmdWhere)
	if ctx.Err() != nil {
		return karte.CheckResult{}, ctx.Err()
	}

	eff := ParseEffective(effOut)
	res := Analyze(eff, ParseWhere(whereOut))

	var b strings.Builder
	b.WriteString("$ sudo " + cmdEffective + "（関係する項目だけ抜き出し）\n")
	for _, k := range watchedKeys {
		if v, ok := eff[k]; ok {
			b.WriteString(k + " " + v + "\n")
		}
	}
	b.WriteString("\n$ sudo grep（設定が書かれている場所）\n")
	if w := strings.TrimRight(whereOut, "\n"); w != "" {
		b.WriteString(w)
	} else {
		b.WriteString("（どのファイルにも書かれていません。初期値が使われています）")
	}
	res.Evidence = b.String()
	return res, nil
}

// Analyze は実際の設定値と、書かれている場所から、カルテを作る。
// eff が nil のときは、設定を読み取れなかったものとして扱う。
func Analyze(eff map[string]string, locs []Location) karte.CheckResult {
	res := karte.CheckResult{CheckID: CheckID, Name: CheckName, Grade: karte.GradeA}

	if eff == nil || eff["passwordauthentication"] == "" {
		f := karte.Describe(karte.Finding{Code: "SSH_CONFIG_UNKNOWN", Grade: karte.GradeC, Params: map[string]string{}})
		res.Grade = f.Grade
		res.Findings = []karte.Finding{f}
		res.Summary = "SSHの設定を読み取れませんでした"
		return res
	}

	yes := func(k string) bool { return eff[k] == "yes" }
	password := yes("passwordauthentication")
	// PAM を使っていると、keyboard-interactive でもパスワードを聞かれる
	kbd := (yes("kbdinteractiveauthentication") || yes("challengeresponseauthentication")) && yes("usepam")
	passwordLike := password || kbd

	var findings []karte.Finding
	add := func(code string, g karte.Grade, params map[string]string) {
		if params == nil {
			params = map[string]string{}
		}
		findings = append(findings, karte.Finding{Code: code, Grade: g, Params: params})
	}

	if password {
		add("SSH_PASSWORD_LOGIN", karte.GradeC, map[string]string{"where": where(locs, "passwordauthentication")})
	} else if kbd {
		key := "kbdinteractiveauthentication"
		if !yes(key) {
			key = "challengeresponseauthentication"
		}
		add("SSH_KBDINTERACTIVE_LOGIN", karte.GradeC, map[string]string{"key": key, "where": where(locs, key)})
	}

	if passwordLike && yes("permitemptypasswords") {
		add("SSH_EMPTY_PASSWORD", karte.GradeE, map[string]string{"where": where(locs, "permitemptypasswords")})
	}

	switch eff["permitrootlogin"] {
	case "yes":
		if passwordLike {
			add("SSH_ROOT_PASSWORD_LOGIN", karte.GradeD, map[string]string{"where": where(locs, "permitrootlogin")})
		} else {
			add("SSH_ROOT_LOGIN", karte.GradeB, map[string]string{"where": where(locs, "permitrootlogin")})
		}
	}

	if eff["pubkeyauthentication"] == "no" {
		add("SSH_PUBKEY_DISABLED", karte.GradeC, map[string]string{"where": where(locs, "pubkeyauthentication")})
	}

	if len(findings) == 0 {
		add("SSH_KEY_ONLY", karte.GradeA, nil)
	}

	for i := range findings {
		findings[i] = karte.Describe(findings[i])
		res.Grade = karte.Worse(res.Grade, findings[i].Grade)
	}
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].Grade > findings[j].Grade })
	res.Findings = findings

	switch {
	case passwordLike:
		res.Summary = "パスワードでログインできる設定です"
	case res.Grade == karte.GradeA:
		res.Summary = "鍵でのみログインできる設定です"
	default:
		res.Summary = fmt.Sprintf("SSHの設定に要確認 %d件", len(findings))
	}
	return res
}

// where は設定が書かれている場所を、説明文に差し込む文にする。
func where(locs []Location, key string) string {
	var hits []string
	for _, l := range locs {
		if l.Key == key {
			hits = append(hits, fmt.Sprintf("%s の %s行目（%s）", l.File, l.Line, l.Value))
		}
	}
	if len(hits) == 0 {
		return "設定ファイルには書かれていません（sshd の初期値が使われています）"
	}
	return strings.Join(hits, "、")
}
