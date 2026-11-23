package packages

import (
	"fmt"
	"time"
)

// 月単位の日付（例：2025年5月）。Ubuntu公式の Release cycle は月までしか書いていない。
type month struct {
	Year  int
	Month time.Month
}

// start はその月の1日（0時・UTC）。
func (m month) start() time.Time {
	return time.Date(m.Year, m.Month, 1, 0, 0, 0, 0, time.UTC)
}

// String は画面に出す書き方（例：2025年5月）。
func (m month) String() string {
	return fmt.Sprintf("%d年%d月", m.Year, int(m.Month))
}

// Release は Ubuntu の版ごとのサポート期限。
type Release struct {
	Version     string // /etc/os-release の VERSION_ID（例：20.04）
	Codename    string // 例：Focal Fossa
	LTS         bool
	StandardEnd month // 通常サポート（無料のセキュリティ更新）の終わり
	ESMEnd      month // Ubuntu Pro（ESM）の終わり。LTS以外は ESM がない（ゼロ値）
}

// releases はサポート期限の表（11/23 決定：アプリの中に持つ）。
//
// 出典：Ubuntu 公式「Ubuntu release cycle」https://ubuntu.com/about/release-cycle （2026/11/23 確認）
// このページに載っている版だけを入れる。載っていない版（25.04 などの短期版）は「判断できない」とする。
// 新しい版が出たら、このページを見て行を足す。
var releases = []Release{
	{"16.04", "Xenial Xerus", true, month{2021, time.April}, month{2026, time.May}},
	{"18.04", "Bionic Beaver", true, month{2023, time.May}, month{2028, time.May}},
	{"20.04", "Focal Fossa", true, month{2025, time.May}, month{2030, time.May}},
	{"22.04", "Jammy Jellyfish", true, month{2027, time.May}, month{2032, time.May}},
	{"24.04", "Noble Numbat", true, month{2029, time.May}, month{2034, time.May}},
	{"26.04", "Resolute Raccoon", true, month{2031, time.May}, month{2036, time.May}},
	{"26.10", "Stonking Stingray", false, month{2027, time.July}, month{}},
}

// SupportState はサポート期限と照らし合わせた結果。
type SupportState int

const (
	SupportUnknown SupportState = iota // 表にない版。判断できない
	SupportActive                      // 通常サポート中
	SupportESMOnly                     // 通常サポートは終了。ESM（Ubuntu Pro）があれば更新が届く
	SupportEnded                       // ESM も含めて終了
)

// Support は版と今日の日付から、サポートの状態を返す。
//
// 期限は月までしかわからないので、その月の1日に終わったものとして扱う（安全側に倒す）。
// 例：20.04 の通常サポートは「2025年5月」なので、2025/5/1 以降は終了とみなす。
func Support(versionID string, now time.Time) (Release, SupportState) {
	for _, r := range releases {
		if r.Version != versionID {
			continue
		}
		switch {
		case now.Before(r.StandardEnd.start()):
			return r, SupportActive
		case r.LTS && now.Before(r.ESMEnd.start()):
			return r, SupportESMOnly
		default:
			return r, SupportEnded
		}
	}
	return Release{}, SupportUnknown
}
