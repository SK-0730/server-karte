// Package karte はカルテ（診断結果）の型と、判定・説明文をまとめる。
//
// 所見は「コード（Code）」と「差し込む値（Params）」だけを持ち、
// 説明文（何が・なぜ・どう直す）は catalog から引く（DATA.md の決定：説明文はDBに保存しない）。
package karte

// Grade は判定。A がいちばん良く、E がいちばん悪い（SCREENS.md 5章）。
type Grade string

const (
	GradeA Grade = "A" // 問題なし
	GradeB Grade = "B" // 軽微
	GradeC Grade = "C" // 要注意
	GradeD Grade = "D" // 危険
	GradeE Grade = "E" // 緊急
)

var gradeRank = map[Grade]int{GradeA: 0, GradeB: 1, GradeC: 2, GradeD: 3, GradeE: 4}

// Worse は、より悪い方の判定を返す。
func Worse(a, b Grade) Grade {
	if gradeRank[b] > gradeRank[a] {
		return b
	}
	return a
}

// GradeLabel は判定の意味を返す。
func GradeLabel(g Grade) string {
	switch g {
	case GradeA:
		return "問題なし"
	case GradeB:
		return "軽微"
	case GradeC:
		return "要注意"
	case GradeD:
		return "危険"
	case GradeE:
		return "緊急"
	}
	return ""
}

// Finding はカルテの1行（所見）。
type Finding struct {
	Code     string            `json:"code"`     // 例：PORT_DB_PUBLIC
	Grade    Grade             `json:"grade"`    // 判定
	Params   map[string]string `json:"params"`   // 説明文に差し込む値
	Evidence string            `json:"evidence"` // 根拠となった出力（画面では伏せない）

	// 以下は catalog から埋める表示用の文。保存はしない。
	Title    string `json:"title"`
	What     string `json:"what"`
	Why      string `json:"why"`
	HowToFix string `json:"howToFix"`
}

// CheckResult は1つの診断（ポート診断など）の結果。
type CheckResult struct {
	CheckID  string    `json:"checkId"`  // ports / sshconfig / files / packages
	Name     string    `json:"name"`     // 例：ポート診断
	Grade    Grade     `json:"grade"`    // 所見の中でいちばん悪い判定
	Summary  string    `json:"summary"`  // 一覧に出す一言
	Findings []Finding `json:"findings"` // 判定の悪い順
	Evidence string    `json:"evidence"` // 診断全体の根拠（実行したコマンドの出力）
}
