package packages

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"app/internal/karte"
	"app/internal/remote"
)

// patient01 の実際の出力（11/23 確認）。日時は JST の 2026-10-15 10:20:13 と、診断した 2026-11-23 を秒数にしたもの。
var (
	stamp1015 = time.Date(2026, time.October, 15, 10, 20, 13, 0, time.FixedZone("JST", 9*3600)).Unix()
	now1123   = time.Date(2026, time.November, 23, 12, 0, 0, 0, time.FixedZone("JST", 9*3600)).Unix()
)

const aptListPatient01 = `一覧表示... 完了
apt-utils/focal-updates 2.0.11 amd64 [2.0.9 からアップグレード可]
tcpdump/focal-updates 4.9.3-4ubuntu0.3 amd64 [4.9.3-4ubuntu0.2 からアップグレード可]
ubuntu-advantage-tools/focal-updates,focal-updates,focal-security,focal-security 37.1ubuntu0~20.04.1 amd64 [27.13.6~20.04.1 からアップグレード可]
`

func codes(res karte.CheckResult) []string {
	var cs []string
	for _, f := range res.Findings {
		cs = append(cs, f.Code)
	}
	return cs
}

func formatInt(n int64) string { return strconv.FormatInt(n, 10) }

func TestParseAptCheck(t *testing.T) {
	c, ok := ParseAptCheck("80;3")
	if !ok || c.Total != 80 || c.Security != 3 || !c.Exact {
		t.Errorf("got %+v %v", c, ok)
	}
	if _, ok := ParseAptCheck("bash: /usr/lib/update-notifier/apt-check: No such file or directory"); ok {
		t.Error("apt-check がないときは読めないはず")
	}
}

func TestParseAptList(t *testing.T) {
	c := ParseAptList(aptListPatient01)
	// 「-security」と表示されたものだけ数えるので、apt-check（3件）より少なくなる
	if c.Total != 3 || c.Security != 1 || c.Exact {
		t.Errorf("got %+v", c)
	}
}

func TestParseDates(t *testing.T) {
	out := formatInt(now1123) + "\n" + formatInt(stamp1015) + " stamp\n" + "1776790597 list\n"
	d := ParseDates(out)
	if d.Now.Unix() != now1123 || d.Updated.Unix() != stamp1015 || d.FromList {
		t.Errorf("got %+v", d)
	}
	// update-success-stamp がないときは、一覧のファイルのいちばん新しい日時で代わりにする
	d = ParseDates(formatInt(now1123) + "\n100 list\n300 list\n200 list\n")
	if d.Updated.Unix() != 300 || !d.FromList {
		t.Errorf("一覧のファイルで代わり: %+v", d)
	}
	if d := ParseDates(""); !d.Updated.IsZero() || !d.Now.IsZero() {
		t.Errorf("空: %+v", d)
	}
}

// patient01 をそのまま診断した場合：サポート切れ（E）＋ セキュリティ3件（D）＋ 一覧が39日前（C）
func TestRunPatient01(t *testing.T) {
	r := &remote.FakeRunner{Outputs: map[string]string{
		cmdAptCheck: "80;3",
		cmdDates:    formatInt(now1123) + "\n" + formatInt(stamp1015) + " stamp\n",
		cmdESM:      "",
		cmdReboot:   "no\n",
	}}
	res, err := Run(context.Background(), r, "20.04")
	if err != nil {
		t.Fatal(err)
	}
	if res.Grade != karte.GradeE {
		t.Errorf("Grade = %s, want E", res.Grade)
	}
	want := "PKG_OS_EOL,PKG_SECURITY_UPDATES,PKG_LIST_STALE"
	if got := strings.Join(codes(res), ","); got != want {
		t.Errorf("codes = %s, want %s", got, want)
	}
	if !strings.Contains(res.Summary, "OSのサポート切れ") || !strings.Contains(res.Summary, "80件") || !strings.Contains(res.Summary, "39日前") {
		t.Errorf("Summary = %q", res.Summary)
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Title+f.What+f.Why+f.HowToFix, "{") {
			t.Errorf("%s に置き換えていない {...} が残っています: %s", f.Code, f.What)
		}
	}
	for _, c := range r.Calls {
		if strings.HasPrefix(c, "sudo ") || strings.Contains(c, "apt update") || strings.Contains(c, "apt-get update") {
			t.Errorf("読み取りのみ・sudo なしのはず: %q", c)
		}
	}
}

func TestRunWithoutAptCheck(t *testing.T) {
	r := &remote.FakeRunner{Outputs: map[string]string{
		// cmdAptCheck は未登録＝実行できない
		cmdAptList: aptListPatient01,
		cmdDates:   formatInt(now1123) + "\n" + formatInt(now1123-3600) + " stamp\n",
		cmdESM:     "",
		cmdReboot:  "no\n",
	}}
	res, err := Run(context.Background(), r, "22.04")
	if err != nil {
		t.Fatal(err)
	}
	if res.Grade != karte.GradeD {
		t.Errorf("Grade = %s, want D", res.Grade)
	}
	if !strings.Contains(res.Findings[0].What, "少なめに数えている可能性") {
		t.Errorf("apt list で数えたことを書き添えるはず: %s", res.Findings[0].What)
	}
	if !strings.Contains(res.Summary, "今日") {
		t.Errorf("Summary = %q", res.Summary)
	}
}

func TestAnalyze(t *testing.T) {
	today := time.Date(2026, time.November, 23, 12, 0, 0, 0, time.UTC)
	fresh := Dates{Now: today, Updated: today.Add(-24 * time.Hour)}
	tests := []struct {
		name  string
		facts Facts
		grade karte.Grade
		codes string
	}{
		{"最新で問題なし", Facts{Version: "24.04", Today: today, CountsOK: true, Counts: Counts{Exact: true}, Dates: fresh},
			karte.GradeA, "PKG_UP_TO_DATE"},
		{"セキュリティ以外の更新だけ", Facts{Version: "24.04", Today: today, CountsOK: true, Counts: Counts{Total: 5, Exact: true}, Dates: fresh},
			karte.GradeB, "PKG_UPDATES"},
		{"再起動待ち", Facts{Version: "24.04", Today: today, CountsOK: true, Counts: Counts{Exact: true}, Dates: fresh, RebootReq: true},
			karte.GradeB, "PKG_REBOOT_REQUIRED"},
		{"一覧が7日前なら古い", Facts{Version: "24.04", Today: today, CountsOK: true, Counts: Counts{Exact: true}, Dates: Dates{Now: today, Updated: today.Add(-7 * 24 * time.Hour)}},
			karte.GradeC, "PKG_LIST_STALE"},
		{"一覧が6日前ならまだ新しい", Facts{Version: "24.04", Today: today, CountsOK: true, Counts: Counts{Exact: true}, Dates: Dates{Now: today, Updated: today.Add(-6 * 24 * time.Hour)}},
			karte.GradeA, "PKG_UP_TO_DATE"},
		{"日時を読めない", Facts{Version: "24.04", Today: today, CountsOK: true, Counts: Counts{Exact: true}},
			karte.GradeC, "PKG_LIST_DATE_UNKNOWN"},
		{"件数を読めない", Facts{Version: "24.04", Today: today, Dates: fresh},
			karte.GradeC, "PKG_COUNT_UNKNOWN"},
		{"表にない版", Facts{Version: "25.04", Today: today, CountsOK: true, Counts: Counts{Exact: true}, Dates: fresh},
			karte.GradeC, "PKG_OS_UNKNOWN"},
		{"20.04 でも ESM があれば問題なし", Facts{Version: "20.04", Today: today, ESM: true, CountsOK: true, Counts: Counts{Exact: true}, Dates: fresh},
			karte.GradeA, "PKG_UP_TO_DATE_ESM"},
		{"16.04 は ESM があっても終了", Facts{Version: "16.04", Today: today, ESM: true, CountsOK: true, Counts: Counts{Exact: true}, Dates: fresh},
			karte.GradeE, "PKG_OS_ESM_ENDED"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := Analyze(tt.facts)
			if res.Grade != tt.grade {
				t.Errorf("Grade = %s, want %s", res.Grade, tt.grade)
			}
			if got := strings.Join(codes(res), ","); got != tt.codes {
				t.Errorf("codes = %s, want %s", got, tt.codes)
			}
			for _, f := range res.Findings {
				if strings.Contains(f.Title+f.What+f.Why+f.HowToFix, "{") {
					t.Errorf("%s に置き換えていない {...} が残っています", f.Code)
				}
			}
		})
	}
}
