// Package files は不要ファイル診断（F07 / WBS 4.3）。
//
// 調べること
//  1. Webサーバー（nginx・Apache）が公開しているフォルダ（root / DocumentRoot の設定）
//  2. 受付票の公開フォルダ（空欄なら /var/www）と、1 のフォルダの中にある
//     .env・秘密鍵・.git・DBのダンプ・バックアップ・phpinfo.php（find）
//
// 見つけたファイルが 1 のフォルダの中にあれば「Webから見える」として重く判定する
// （/var/www/app/.env でも、公開しているのが /var/www/app/public なら見えない）。
// Docker のコンテナの中は調べない（11/19 決定）。
//
// 実行するのは読み取りだけのコマンド（設計方針）。
package files

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"app/internal/karte"
	"app/internal/remote"
)

const (
	CheckID   = "files"
	CheckName = "不要ファイル診断"

	// DefaultRoot は受付票の公開フォルダが空欄のときに探す場所（11/9 決定）。
	DefaultRoot = "/var/www"

	// 公開フォルダの設定を探す。ないフォルダがあっても grep は見つかった分を出す。
	// sites-enabled の中身は sites-available へのシンボリックリンクなので、-R（リンクもたどる）にする
	// （-r だとたどらず、Ubuntu の初期設定の root を見落とす。11/19 patient01 で発生）
	cmdDocRoots = `grep -RhiE '^[[:space:]]*(root|documentroot)[[:space:]]' /etc/nginx/sites-enabled /etc/nginx/conf.d /etc/apache2/sites-enabled`

	maxDepth  = 8  // 深すぎるフォルダまでは探さない
	maxListed = 10 // 所見に並べるファイルの数
)

// safePath は、コマンドに入れてよいフォルダの書き方（絶対パスで、記号は . _ - @ + / だけ）。
// 受付票の入力はサーバーのコマンドに入るので、これ以外は使わない（コマンドの差し込みを防ぐ）。
var safePath = regexp.MustCompile(`^/[A-Za-z0-9._@+/-]*$`)

// ValidRoot はフォルダの書き方が安全かを返す。
func ValidRoot(p string) bool {
	return safePath.MatchString(p) && !strings.Contains(p, "..")
}

// Kind は見つけたファイルの種類。
type Kind int

const (
	KindEnv     Kind = iota // .env（パスワードなどの設定）
	KindKey                 // 秘密鍵
	KindGit                 // .git フォルダ
	KindDump                // DBのダンプ
	KindBackup              // バックアップ・圧縮ファイル
	KindPHPInfo             // phpinfo.php
)

// 探すファイルの名前（find の -name に渡す）と種類。
var patterns = []struct {
	name string
	kind Kind
}{
	{".env", KindEnv}, {".env.*", KindEnv},
	{"id_rsa", KindKey}, {"id_ecdsa", KindKey}, {"id_ed25519", KindKey}, {"*.pem", KindKey}, {"*.key", KindKey},
	{".git", KindGit},
	{"*.sql", KindDump}, {"*.sql.gz", KindDump},
	{"*.bak", KindBackup}, {"*~", KindBackup}, {"*.old", KindBackup}, {"*.orig", KindBackup}, {"*.swp", KindBackup},
	{"*.zip", KindBackup}, {"*.tar", KindBackup}, {"*.tar.gz", KindBackup}, {"*.tgz", KindBackup},
	{"phpinfo.php", KindPHPInfo},
}

// 見本として置かれるもので、中身は空のことが多い
var templates = map[string]bool{".env.example": true, ".env.sample": true, ".env.dist": true, ".env.template": true}

// KindOf はファイル名から種類を返す。対象外なら false。
func KindOf(p string) (Kind, bool) {
	base := path.Base(p)
	if templates[base] {
		return 0, false
	}
	for _, pt := range patterns {
		if ok, _ := path.Match(pt.name, base); ok {
			return pt.kind, true
		}
	}
	return 0, false
}

// findCommand は roots の中から対象のファイルを探すコマンドを作る。
// node_modules と vendor（ライブラリ置き場）は数が多いので入らない。.git は中まで入らない。
func findCommand(roots []string) string {
	var names []string
	for _, pt := range patterns {
		names = append(names, "-name '"+pt.name+"'")
	}
	return "find " + strings.Join(roots, " ") + " -maxdepth " + strconv.Itoa(maxDepth) +
		` \( -name node_modules -o -name vendor \) -prune -o \( ` + strings.Join(names, " -o ") + ` \) -print -prune`
}

// ParseDocRoots は grep で取り出した root / DocumentRoot の行から、公開フォルダの一覧を返す。
//
//	root /var/www/html;
//	DocumentRoot "/var/www/site"
func ParseDocRoots(out string) []string {
	seen := map[string]bool{}
	var roots []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		p := strings.Trim(strings.TrimSuffix(f[1], ";"), `"'`)
		p = strings.TrimSuffix(p, "/")
		if p == "" || !ValidRoot(p) || seen[p] { // $document_root などの変数は読めないので外す
			continue
		}
		seen[p] = true
		roots = append(roots, p)
	}
	sort.Strings(roots)
	return roots
}

// Hit は見つけた1つのファイル。
type Hit struct {
	Path   string
	Kind   Kind
	Public bool   // Webから見える場所にあるか
	Under  string // Public のとき、どの公開フォルダの中か
}

// Classify は find の出力を種類ごとに分け、公開フォルダの中にあるかを調べる。
func Classify(findOut string, docRoots []string) []Hit {
	seen := map[string]bool{}
	var hits []Hit
	for _, line := range strings.Split(findOut, "\n") {
		p := strings.TrimSpace(line)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		kind, ok := KindOf(p)
		if !ok {
			continue
		}
		h := Hit{Path: p, Kind: kind}
		for _, r := range docRoots {
			if strings.HasPrefix(p, r+"/") {
				h.Public, h.Under = true, r
				break
			}
		}
		hits = append(hits, h)
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Path < hits[j].Path })
	return hits
}

// Run は不要ファイル診断を行う。webRoot は受付票の公開フォルダ（空欄可）。
func Run(ctx context.Context, r remote.Runner, webRoot string) (karte.CheckResult, error) {
	var ev strings.Builder

	userRoot := strings.TrimSuffix(strings.TrimSpace(webRoot), "/")
	if userRoot == "" {
		userRoot = DefaultRoot
	}
	if !ValidRoot(userRoot) {
		res := Analyze(nil, nil, userRoot, rootInvalid)
		res.Evidence = "公開フォルダの書き方が正しくないため、診断しませんでした：" + userRoot
		return res, nil
	}

	// ① Webサーバーの公開フォルダ（なければ空。エラーは「設定が見つからない」として扱う）
	docOut, _ := r.RunSudo(ctx, cmdDocRoots)
	if ctx.Err() != nil {
		return karte.CheckResult{}, ctx.Err()
	}
	docRoots := ParseDocRoots(docOut)
	ev.WriteString("$ sudo grep（Webサーバーの公開フォルダの設定）\n")
	if s := strings.TrimRight(docOut, "\n"); s != "" {
		ev.WriteString(s + "\n")
	} else {
		ev.WriteString("（見つかりませんでした）\n")
	}

	// ② 探す場所：受付票のフォルダと公開フォルダのうち、実際にあるもの
	var roots []string
	userRootState := rootOK
	for _, p := range append([]string{userRoot}, docRoots...) {
		if contains(roots, p) || insideAny(p, roots) {
			continue
		}
		if _, err := r.RunSudo(ctx, "test -d "+p); err != nil {
			if ctx.Err() != nil {
				return karte.CheckResult{}, ctx.Err()
			}
			if p == userRoot {
				userRootState = rootMissing
			}
			ev.WriteString("（" + p + " はありません）\n")
			continue
		}
		roots = append(roots, p)
	}

	var hits []Hit
	if len(roots) > 0 {
		cmd := findCommand(roots)
		out, err := r.RunSudo(ctx, cmd)
		if ctx.Err() != nil {
			return karte.CheckResult{}, ctx.Err()
		}
		if err != nil && strings.TrimSpace(out) == "" {
			return karte.CheckResult{}, fmt.Errorf("ファイルを探せませんでした: %w", err)
		}
		hits = Classify(out, docRoots)
		ev.WriteString("\n$ sudo " + cmd + "\n")
		if s := strings.TrimRight(out, "\n"); s != "" {
			ev.WriteString(s)
		} else {
			ev.WriteString("（見つかりませんでした）")
		}
	}

	res := Analyze(hits, docRoots, userRoot, userRootState)
	res.Evidence = ev.String()
	return res, nil
}

type rootState int

const (
	rootOK rootState = iota
	rootMissing
	rootInvalid
)

// Analyze は見つけたファイルから、カルテを作る。
func Analyze(hits []Hit, docRoots []string, userRoot string, state rootState) karte.CheckResult {
	res := karte.CheckResult{CheckID: CheckID, Name: CheckName, Grade: karte.GradeA}

	var findings []karte.Finding
	add := func(code string, g karte.Grade, params map[string]string) {
		if params == nil {
			params = map[string]string{}
		}
		findings = append(findings, karte.Finding{Code: code, Grade: g, Params: params})
	}

	switch state {
	case rootInvalid:
		add("FILES_ROOT_INVALID", karte.GradeB, map[string]string{"root": userRoot})
	case rootMissing:
		add("FILES_ROOT_MISSING", karte.GradeB, map[string]string{"root": userRoot})
	}

	// Webから見える場所にあるものは、種類ごとに1つの所見にまとめる
	public := map[Kind][]Hit{}
	var private []Hit
	for _, h := range hits {
		if h.Public {
			public[h.Kind] = append(public[h.Kind], h)
		} else if h.Kind == KindEnv || h.Kind == KindKey || h.Kind == KindDump {
			private = append(private, h) // 見えない場所の .git・バックアップ・phpinfo は普通の使い方なので出さない
		}
	}
	publicRule := []struct {
		kind  Kind
		code  string
		grade karte.Grade
	}{
		{KindEnv, "FILE_ENV_PUBLIC", karte.GradeE},
		{KindKey, "FILE_KEY_PUBLIC", karte.GradeE},
		{KindGit, "FILE_GIT_PUBLIC", karte.GradeE},
		{KindDump, "FILE_DUMP_PUBLIC", karte.GradeD},
		{KindBackup, "FILE_BACKUP_PUBLIC", karte.GradeD},
		{KindPHPInfo, "FILE_PHPINFO_PUBLIC", karte.GradeC},
	}
	publicCount := 0
	for _, rule := range publicRule {
		hs := public[rule.kind]
		if len(hs) == 0 {
			continue
		}
		publicCount += len(hs)
		add(rule.code, rule.grade, map[string]string{"files": list(hs), "count": strconv.Itoa(len(hs)), "docroot": hs[0].Under})
	}
	if len(private) > 0 {
		add("FILE_SENSITIVE_PRIVATE", karte.GradeB, map[string]string{"files": list(private), "count": strconv.Itoa(len(private))})
	}

	if len(docRoots) == 0 && state != rootInvalid {
		add("FILES_NO_DOCROOT", karte.GradeA, map[string]string{"root": userRoot})
	}
	if publicCount == 0 && len(private) == 0 && state == rootOK && len(docRoots) > 0 {
		add("FILES_NONE", karte.GradeA, map[string]string{"docroots": strings.Join(docRoots, "、")})
	}

	for i := range findings {
		findings[i] = karte.Describe(findings[i])
		res.Grade = karte.Worse(res.Grade, findings[i].Grade)
	}
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].Grade > findings[j].Grade })
	res.Findings = findings

	switch {
	case publicCount > 0:
		res.Summary = fmt.Sprintf("Webから見えるファイル %d件", publicCount)
	case state == rootInvalid:
		res.Summary = "公開フォルダの書き方が正しくありません"
	case len(private) > 0:
		res.Summary = fmt.Sprintf("Webからは見えない場所に、取り扱い注意のファイル %d件", len(private))
	case len(docRoots) == 0:
		res.Summary = "Webサーバーの公開フォルダが見つかりませんでした"
	default:
		res.Summary = "Webから見える不要なファイルはありません"
	}
	return res
}

// list は所見に並べる文を作る。多すぎるときは途中までにする。
func list(hs []Hit) string {
	var lines []string
	for i, h := range hs {
		if i == maxListed {
			lines = append(lines, fmt.Sprintf("ほか %d件（根拠に全件あります）", len(hs)-maxListed))
			break
		}
		lines = append(lines, "・"+h.Path)
	}
	return strings.Join(lines, "\n")
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// insideAny は p が roots のどれかの中にあるかを返す（同じ場所を2回探さないため）。
func insideAny(p string, roots []string) bool {
	for _, r := range roots {
		if strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
}
