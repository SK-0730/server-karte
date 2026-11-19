package files

import (
	"context"
	"errors"
	"strings"
	"testing"

	"app/internal/karte"
	"app/internal/remote"
)

// nginx（Ubuntu の初期設定）と、Laravel 風のサイトを想定した grep の出力。
const docOut = `	root /var/www/html;
        root /var/www/app/public;
	# root /var/www/old;
	root $document_root;
`

// わざと穴を開けた状態を想定した find の出力。
const findHoles = `/var/www/html/.env
/var/www/html/.git
/var/www/html/index.php.bak
/var/www/html/.index.php.swp
/var/www/html/backup.zip
/var/www/html/db.sql
/var/www/html/phpinfo.php
/var/www/html/server.key
/var/www/app/.env
/var/www/app/.env.example
/var/www/app/.git
/var/www/app/public/old.tar.gz
`

func codes(res karte.CheckResult) []string {
	var cs []string
	for _, f := range res.Findings {
		cs = append(cs, f.Code)
	}
	return cs
}

func TestParseDocRoots(t *testing.T) {
	got := ParseDocRoots(docOut)
	// "# root" はコメントだが grep の正規表現では拾わない。$document_root は変数なので外す
	want := []string{"/var/www/app/public", "/var/www/html"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%v, want %v", got, want)
	}
	if got := ParseDocRoots(`DocumentRoot "/srv/site/"`); len(got) != 1 || got[0] != "/srv/site" {
		t.Errorf("Apache の書き方: %v", got)
	}
}

func TestValidRoot(t *testing.T) {
	ok := []string{"/var/www", "/var/www/html", "/srv/my-site_2", "/home/taro/public.html"}
	ng := []string{"", "var/www", "/var/www; rm -rf /", "/var/www/$(id)", "/var/www/../../etc", "/var/www dir", "/var/'www'", "/var/www|x"}
	for _, p := range ok {
		if !ValidRoot(p) {
			t.Errorf("%q は使えるはず", p)
		}
	}
	for _, p := range ng {
		if ValidRoot(p) {
			t.Errorf("%q は使えないはず", p)
		}
	}
}

func TestKindOf(t *testing.T) {
	cases := map[string]Kind{
		"/x/.env": KindEnv, "/x/.env.production": KindEnv, "/x/id_rsa": KindKey, "/x/server.pem": KindKey,
		"/x/.git": KindGit, "/x/db.sql.gz": KindDump, "/x/index.php~": KindBackup, "/x/site.tgz": KindBackup,
		"/x/phpinfo.php": KindPHPInfo,
	}
	for p, want := range cases {
		if got, ok := KindOf(p); !ok || got != want {
			t.Errorf("%s: %v %v, want %v", p, got, ok, want)
		}
	}
	for _, p := range []string{"/x/.env.example", "/x/index.php", "/x/id_rsa.pub"} {
		if _, ok := KindOf(p); ok {
			t.Errorf("%s は対象外のはず", p)
		}
	}
}

func TestAnalyzeHoles(t *testing.T) {
	roots := ParseDocRoots(docOut)
	res := Analyze(Classify(findHoles, roots), roots, "/var/www", rootOK)
	if res.Grade != karte.GradeE {
		t.Errorf("判定 = %s, want E", res.Grade)
	}
	want := []string{
		"FILE_ENV_PUBLIC", "FILE_KEY_PUBLIC", "FILE_GIT_PUBLIC", // E
		"FILE_DUMP_PUBLIC", "FILE_BACKUP_PUBLIC", // D
		"FILE_PHPINFO_PUBLIC",    // C
		"FILE_SENSITIVE_PRIVATE", // B：/var/www/app/.env は公開フォルダ（public）の外
	}
	if got := codes(res); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("所見 = %v\nwant %v", got, want)
	}
	for _, f := range res.Findings {
		switch f.Code {
		case "FILE_BACKUP_PUBLIC":
			// public の中の old.tar.gz も「見える」に入る。.index.php.swp も拾う
			if f.Params["count"] != "4" || !strings.Contains(f.What, "/var/www/app/public/old.tar.gz") {
				t.Errorf("バックアップ: %s", f.What)
			}
		case "FILE_SENSITIVE_PRIVATE":
			if !strings.Contains(f.What, "/var/www/app/.env") || strings.Contains(f.What, ".env.example") {
				t.Errorf("見えない場所: %s", f.What)
			}
		}
		if strings.Contains(f.What+f.Why+f.HowToFix, "{") {
			t.Errorf("差し込み忘れ: %s %s", f.Code, f.What)
		}
	}
	// /var/www/app/.git は公開フォルダの外なので出さない
	if strings.Contains(res.Findings[2].What, "/var/www/app/.git") {
		t.Errorf("見えない .git まで出ている: %s", res.Findings[2].What)
	}
	if res.Summary != "Webから見えるファイル 9件" {
		t.Errorf("一言 = %q", res.Summary)
	}
}

func TestAnalyzeClean(t *testing.T) {
	res := Analyze(nil, []string{"/var/www/html"}, "/var/www", rootOK)
	if res.Grade != karte.GradeA || codes(res)[0] != "FILES_NONE" {
		t.Errorf("%v %s", codes(res), res.Grade)
	}
}

func TestAnalyzeNoWebServer(t *testing.T) {
	// Webサーバーがない（または Docker の中）。見つけたものは「見えない」扱い
	res := Analyze(Classify("/var/www/.env\n", nil), nil, "/var/www", rootOK)
	if got := codes(res); strings.Join(got, ",") != "FILE_SENSITIVE_PRIVATE,FILES_NO_DOCROOT" || res.Grade != karte.GradeB {
		t.Errorf("%v %s", got, res.Grade)
	}
}

func TestListLimit(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 13; i++ {
		b.WriteString("/var/www/html/f" + string(rune('a'+i)) + ".bak\n")
	}
	res := Analyze(Classify(b.String(), []string{"/var/www/html"}), []string{"/var/www/html"}, "/var/www", rootOK)
	if !strings.Contains(res.Findings[0].What, "ほか 3件") {
		t.Errorf("%s", res.Findings[0].What)
	}
}

func fakeRunner(find string) *remote.FakeRunner {
	return &remote.FakeRunner{SudoOutputs: map[string]string{
		cmdDocRoots:                                         docOut,
		"test -d /var/www":                                  "",
		findCommand([]string{"/var/www"}):                   find,
		findCommand([]string{"/srv/site"}):                  find,
		findCommand([]string{"/srv/site", "/var/www/html"}): find,
	}}
}

func TestRun(t *testing.T) {
	r := fakeRunner(findHoles)
	res, err := Run(context.Background(), r, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Grade != karte.GradeE || res.CheckID != CheckID {
		t.Errorf("%+v", res)
	}
	// 公開フォルダは /var/www の中なので、find は /var/www の1回だけ
	finds := 0
	for _, c := range r.Calls {
		if !strings.HasPrefix(c, "sudo ") {
			t.Errorf("sudo で実行するはず: %s", c)
		}
		if strings.HasPrefix(c, "sudo find ") {
			finds++
		}
	}
	if finds != 1 {
		t.Errorf("find の回数 = %d, %v", finds, r.Calls)
	}
	if !strings.Contains(res.Evidence, "root /var/www/html;") || !strings.Contains(res.Evidence, "/var/www/html/.env") {
		t.Errorf("根拠: %s", res.Evidence)
	}
}

func TestRunUserRootMissing(t *testing.T) {
	// /srv/site は無い（test -d が未登録＝失敗）。公開フォルダ /var/www/html などだけを探す
	r := fakeRunner("")
	r.SudoOutputs["test -d /var/www/html"] = ""
	r.SudoOutputs["test -d /var/www/app/public"] = ""
	r.SudoOutputs[findCommand([]string{"/var/www/app/public", "/var/www/html"})] = ""
	res, err := Run(context.Background(), r, "/srv/site/")
	if err != nil {
		t.Fatal(err)
	}
	if got := codes(res); len(got) != 1 || got[0] != "FILES_ROOT_MISSING" || res.Grade != karte.GradeB {
		t.Errorf("%v %s", got, res.Grade)
	}
}

func TestRunInvalidRoot(t *testing.T) {
	r := &remote.FakeRunner{}
	res, err := Run(context.Background(), r, "/var/www; rm -rf /")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Calls) != 0 {
		t.Errorf("コマンドを1つも実行しないはず: %v", r.Calls)
	}
	if got := codes(res); len(got) != 1 || got[0] != "FILES_ROOT_INVALID" {
		t.Errorf("%v", got)
	}
}

type errRunner struct{ *remote.FakeRunner }

func (e errRunner) RunSudo(ctx context.Context, cmd string) (string, error) {
	if strings.HasPrefix(cmd, "find ") {
		return "", errors.New("接続が切れました")
	}
	return e.FakeRunner.RunSudo(ctx, cmd)
}

func TestRunFindFails(t *testing.T) {
	if _, err := Run(context.Background(), errRunner{fakeRunner("")}, ""); err == nil {
		t.Error("find が失敗したらエラーを返すはず")
	}
}

// patient01（Ubuntu 20.04、nginx・Apache の初期設定）で 11/19 に実際に取った出力。
const docPatient01 = "\troot /var/www/html;\n\tDocumentRoot /var/www/html\n"

const findPatient01 = `/var/www/html/phpinfo.php
/var/www/html/.git
/var/www/html/backup.sql
/var/www/html/.env
/var/www/html/index.html.bak
/var/www/app/.env
`

func TestPatient01(t *testing.T) {
	roots := ParseDocRoots(docPatient01)
	if len(roots) != 1 || roots[0] != "/var/www/html" {
		t.Fatalf("nginx と Apache の同じ場所は1つにまとめる: %v", roots)
	}
	res := Analyze(Classify(findPatient01, roots), roots, "/var/www", rootOK)
	want := []string{"FILE_ENV_PUBLIC", "FILE_GIT_PUBLIC", "FILE_DUMP_PUBLIC", "FILE_BACKUP_PUBLIC", "FILE_PHPINFO_PUBLIC", "FILE_SENSITIVE_PRIVATE"}
	if got := codes(res); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("所見 = %v\nwant %v", got, want)
	}
	if res.Grade != karte.GradeE || res.Summary != "Webから見えるファイル 5件" {
		t.Errorf("%s %q", res.Grade, res.Summary)
	}
}
