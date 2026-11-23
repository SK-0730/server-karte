package packages

import (
	"testing"
	"time"
)

func day(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 12, 0, 0, 0, time.UTC)
}

func TestSupport(t *testing.T) {
	tests := []struct {
		name    string
		version string
		now     time.Time
		want    SupportState
	}{
		// patient01（20.04）を今日（2026/11/23）診断した場合
		{"20.04 は通常サポート終了・ESMのみ", "20.04", day(2026, time.November, 23), SupportESMOnly},
		{"20.04 期限の前月は通常サポート中", "20.04", day(2025, time.April, 30), SupportActive},
		{"20.04 期限の月に入ったら終了とみなす", "20.04", day(2025, time.May, 1), SupportESMOnly},
		{"20.04 ESM も終了", "20.04", day(2030, time.May, 1), SupportEnded},
		{"22.04 は通常サポート中", "22.04", day(2026, time.November, 23), SupportActive},
		{"24.04 は通常サポート中", "24.04", day(2026, time.November, 23), SupportActive},
		{"16.04 は ESM のみ（2026年5月の前）", "16.04", day(2026, time.April, 30), SupportESMOnly},
		{"16.04 は ESM も終了", "16.04", day(2026, time.November, 23), SupportEnded},
		{"短期版は ESM がないので期限後は終了", "26.10", day(2027, time.July, 1), SupportEnded},
		{"短期版の期限前", "26.10", day(2026, time.November, 23), SupportActive},
		{"表にない版は判断できない", "25.04", day(2026, time.November, 23), SupportUnknown},
		{"空欄も判断できない", "", day(2026, time.November, 23), SupportUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got := Support(tt.version, tt.now)
			if got != tt.want {
				t.Errorf("Support(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestMonthString(t *testing.T) {
	r, _ := Support("20.04", day(2026, time.November, 23))
	if got := r.StandardEnd.String(); got != "2025年5月" {
		t.Errorf("StandardEnd = %q, want 2025年5月", got)
	}
}
