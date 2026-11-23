// Package packages はパッケージ更新診断（F08 / WBS 4.4）。
//
// 調べること
//  1. OS のサポート期限（アプリの中の表と /etc/os-release の版を照らし合わせる。support.go）
//  2. ESM（Ubuntu Pro）の設定があるか（apt の設定ファイルに esm.ubuntu.com/infra があるか）
//  3. 未適用の更新・セキュリティ更新の件数（apt-check。なければ apt list --upgradable）
//  4. 更新の一覧を最後に新しくした日時（update-success-stamp）
//  5. 再起動待ちか（/var/run/reboot-required）
//
// apt update はしない（11/9 決定。読み取りのみ）。サーバーに残っている一覧をそのまま読むので、
// 一覧が古いと結果も古くなる。そのため、一覧の日付も所見として出す。
// 判定の基準は 11/23 決定（ARCHITECTURE.md 5章の2）。
package packages

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"app/internal/karte"
	"app/internal/remote"
)

const (
	CheckID   = "packages"
	CheckName = "パッケージ更新診断"

	// StaleDays 日以上前の一覧は「古い」とする（11/23 決定）。
	// Ubuntu の自動更新は通常1日1回一覧を新しくするので、1週間あいていれば止まっている疑いがある。
	StaleDays = 7

	// Ubuntu のログイン時の「◯件のセキュリティ更新」と同じ数え方。sudo は要らない。
	// 機械向けの出力「更新;セキュリティ更新」（例：80;3）を標準エラーに出すので、2>&1 で受け取る。
	// （人向けの --human-readable は日本語などに訳されるので使わない）
	cmdAptCheck = "/usr/lib/update-notifier/apt-check 2>&1"
	// apt-check がないときの代わり。表示の「-security」で数えるので、セキュリティ更新を少なめに数えることがある
	cmdAptList = "apt list --upgradable 2>/dev/null"
	// 日時はサーバーの時計で比べる（パソコンとサーバーの時計がずれていても、何日前かを正しく出す）
	cmdDates = "date +%s; stat -c '%Y stamp' /var/lib/apt/periodic/update-success-stamp 2>/dev/null; stat -c '%Y list' /var/lib/apt/lists/*_InRelease 2>/dev/null; true"
	// コメント行（#）は除く。.list と .sources（URIs: の行）の両方の書き方に合う
	cmdESM    = `grep -rhsE '^[^#]*esm\.ubuntu\.com/infra' /etc/apt/sources.list /etc/apt/sources.list.d`
	cmdReboot = "test -e /var/run/reboot-required && echo yes || echo no"
)

// Counts は未適用の更新の件数。
type Counts struct {
	Total    int
	Security int
	Exact    bool // apt-check で数えた（false なら apt list の表示で数えた）
}

var aptCheckOut = regexp.MustCompile(`(?m)^\s*(\d+);(\d+)\s*$`)

// ParseAptCheck は apt-check の機械向けの出力（例：80;3）を読む。
func ParseAptCheck(out string) (Counts, bool) {
	m := aptCheckOut.FindStringSubmatch(out)
	if m == nil {
		return Counts{}, false
	}
	total, _ := strconv.Atoi(m[1])
	sec, _ := strconv.Atoi(m[2])
	return Counts{Total: total, Security: sec, Exact: true}, true
}

// ParseAptList は apt list --upgradable の出力を数える。
// 例：tcpdump/focal-updates 4.9.3-4ubuntu0.3 amd64 [...]（「パッケージ名/置き場所 版 ...」の行）
func ParseAptList(out string) Counts {
	var c Counts
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || !strings.Contains(f[0], "/") {
			continue // 「一覧表示... 完了」などの行
		}
		c.Total++
		_, suites, _ := strings.Cut(f[0], "/")
		if strings.Contains(suites, "-security") {
			c.Security++
		}
	}
	return c
}

// Dates はサーバーの時計での日時。
type Dates struct {
	Now      time.Time // サーバーの今の時刻（読めなければゼロ値）
	Updated  time.Time // 一覧を最後に新しくした日時（読めなければゼロ値）
	FromList bool      // update-success-stamp がなく、一覧のファイルの日時で代わりにした
}

// ParseDates は cmdDates の出力を読む。
func ParseDates(out string) Dates {
	var d Dates
	var listMax int64
	for i, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		n, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			continue
		}
		switch {
		case i == 0 && len(f) == 1:
			d.Now = time.Unix(n, 0)
		case len(f) == 2 && f[1] == "stamp":
			d.Updated = time.Unix(n, 0)
		case len(f) == 2 && f[1] == "list" && n > listMax:
			listMax = n
		}
	}
	if d.Updated.IsZero() && listMax > 0 {
		d.Updated = time.Unix(listMax, 0)
		d.FromList = true
	}
	return d
}

// Facts は Run で集めた情報。判定は Analyze で行う。
type Facts struct {
	Version   string // /etc/os-release の VERSION_ID
	Today     time.Time
	ESM       bool
	Counts    Counts
	CountsOK  bool // 件数を読めた
	Dates     Dates
	RebootReq bool
}

// Run はパッケージ更新診断を行う。versionID は OS判定で読んだ版（例：20.04）。
func Run(ctx context.Context, r remote.Runner, versionID string) (karte.CheckResult, error) {
	facts := Facts{Version: versionID, Today: time.Now()}
	var ev strings.Builder
	write := func(cmd, out, empty string) {
		ev.WriteString("$ " + cmd + "\n")
		if s := strings.TrimRight(out, "\n"); s != "" {
			ev.WriteString(s + "\n\n")
		} else {
			ev.WriteString(empty + "\n\n")
		}
	}

	// ① 件数。apt-check がなければ apt list で代わりに数える
	out, err := r.Run(ctx, cmdAptCheck)
	if ctx.Err() != nil {
		return karte.CheckResult{}, ctx.Err()
	}
	if c, ok := ParseAptCheck(out); err == nil && ok {
		facts.Counts, facts.CountsOK = c, true
		write(cmdAptCheck, out, "")
	} else {
		write(cmdAptCheck, out, "（実行できませんでした）")
		listOut, listErr := r.Run(ctx, cmdAptList)
		if ctx.Err() != nil {
			return karte.CheckResult{}, ctx.Err()
		}
		if listErr == nil {
			facts.Counts, facts.CountsOK = ParseAptList(listOut), true
		}
		write(cmdAptList, listOut, "（更新はありません、または実行できませんでした）")
	}

	// ② 日時
	dateOut, _ := r.Run(ctx, cmdDates)
	if ctx.Err() != nil {
		return karte.CheckResult{}, ctx.Err()
	}
	facts.Dates = ParseDates(dateOut)
	write("date / stat（サーバーの今の時刻と、更新の一覧の日時。数字は1970年からの秒数）", dateOut, "（読み取れませんでした）")

	// ③ ESM（見つからないとき grep は終了コード1を返すので、エラーは「設定なし」として扱う）
	esmOut, _ := r.Run(ctx, cmdESM)
	if ctx.Err() != nil {
		return karte.CheckResult{}, ctx.Err()
	}
	facts.ESM = strings.TrimSpace(esmOut) != ""
	write("grep（ESM の設定）", esmOut, "（設定はありません）")

	// ④ 再起動待ち
	rbOut, _ := r.Run(ctx, cmdReboot)
	if ctx.Err() != nil {
		return karte.CheckResult{}, ctx.Err()
	}
	facts.RebootReq = strings.TrimSpace(rbOut) == "yes"
	write(cmdReboot, rbOut, "（読み取れませんでした）")

	res := Analyze(facts)
	res.Evidence = strings.TrimRight(ev.String(), "\n")
	return res, nil
}

// Analyze は集めた情報から、カルテを作る。
//
// 判定（11/23 決定）
//   - E：OS のサポートが切れていて、ESM もない
//   - D：未適用のセキュリティ更新がある
//   - C：一覧が古い（7日以上）、または件数・日時・版を読めない
//   - B：セキュリティ以外の更新だけがある、または再起動待ち
//   - A：上のどれにも当たらない
func Analyze(f Facts) karte.CheckResult {
	res := karte.CheckResult{CheckID: CheckID, Name: CheckName, Grade: karte.GradeA}

	var findings []karte.Finding
	add := func(code string, g karte.Grade, params map[string]string) {
		if params == nil {
			params = map[string]string{}
		}
		findings = append(findings, karte.Finding{Code: code, Grade: g, Params: params})
	}

	// ① OS のサポート期限
	rel, state := Support(f.Version, f.Today)
	osParams := map[string]string{
		"version":     f.Version,
		"codename":    rel.Codename,
		"standardEnd": rel.StandardEnd.String(),
		"esmEnd":      rel.ESMEnd.String(),
	}
	eol := false
	switch state {
	case SupportUnknown:
		if f.Version == "" {
			osParams["version"] = "（不明）"
		}
		add("PKG_OS_UNKNOWN", karte.GradeC, osParams)
	case SupportESMOnly:
		if !f.ESM {
			add("PKG_OS_EOL", karte.GradeE, osParams)
			eol = true
		}
	case SupportEnded:
		if rel.LTS {
			add("PKG_OS_ESM_ENDED", karte.GradeE, osParams)
		} else {
			add("PKG_OS_INTERIM_ENDED", karte.GradeE, osParams)
		}
		eol = true
	}

	// ② 一覧の日付（件数の説明にも入れる）
	age := ""
	days := -1
	if !f.Dates.Updated.IsZero() {
		now := f.Dates.Now
		if now.IsZero() {
			now = f.Today
		}
		days = int(now.Sub(f.Dates.Updated).Hours() / 24)
		if days < 0 {
			days = 0
		}
		age = fmt.Sprintf("%d日前", days)
		if days == 0 {
			age = "今日"
		}
	}
	dateParams := map[string]string{
		"days":    strconv.Itoa(days),
		"updated": f.Dates.Updated.Format("2006/01/02 15:04"),
		"age":     age,
		"stale":   strconv.Itoa(StaleDays),
	}
	switch {
	case days < 0:
		add("PKG_LIST_DATE_UNKNOWN", karte.GradeC, dateParams)
	case days >= StaleDays:
		add("PKG_LIST_STALE", karte.GradeC, dateParams)
	}

	// ③ 件数
	countParams := map[string]string{
		"total":    strconv.Itoa(f.Counts.Total),
		"security": strconv.Itoa(f.Counts.Security),
		"note":     "",
		"asOf":     "",
	}
	if age != "" {
		countParams["asOf"] = "（" + age + "の一覧をもとにしています）"
	}
	if !f.Counts.Exact {
		countParams["note"] = "\n※ apt-check（Ubuntu の数え方）が使えなかったため、apt list の表示で数えました。セキュリティ更新を少なめに数えている可能性があります。"
	}
	switch {
	case !f.CountsOK:
		add("PKG_COUNT_UNKNOWN", karte.GradeC, nil)
	case f.Counts.Security > 0:
		add("PKG_SECURITY_UPDATES", karte.GradeD, countParams)
	case f.Counts.Total > 0:
		add("PKG_UPDATES", karte.GradeB, countParams)
	}

	if f.RebootReq {
		add("PKG_REBOOT_REQUIRED", karte.GradeB, nil)
	}

	if len(findings) == 0 {
		p := map[string]string{"age": age, "codename": rel.Codename, "version": f.Version, "standardEnd": rel.StandardEnd.String()}
		if state == SupportESMOnly {
			add("PKG_UP_TO_DATE_ESM", karte.GradeA, p)
		} else {
			add("PKG_UP_TO_DATE", karte.GradeA, p)
		}
	}

	for i := range findings {
		findings[i] = karte.Describe(findings[i])
		res.Grade = karte.Worse(res.Grade, findings[i].Grade)
	}
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].Grade > findings[j].Grade })
	res.Findings = findings

	// 一覧に出す一言（SCREENS.md S04 の例：未適用の更新 35件 (10日前)）
	var parts []string
	if eol {
		parts = append(parts, "OSのサポート切れ")
	}
	if f.CountsOK {
		s := fmt.Sprintf("未適用の更新 %d件", f.Counts.Total)
		if f.Counts.Security > 0 {
			s += fmt.Sprintf("（セキュリティ %d件）", f.Counts.Security)
		}
		parts = append(parts, s)
	} else {
		parts = append(parts, "更新の件数を読み取れませんでした")
	}
	res.Summary = strings.Join(parts, "・")
	if age != "" {
		res.Summary += "（" + age + "）"
	}
	return res
}
