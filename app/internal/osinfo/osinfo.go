// Package osinfo は診断対象サーバーのOSを判定する（F04 / WBS 3.3）。
package osinfo

import (
	"bufio"
	"context"
	"fmt"
	"strings"

	"app/internal/remote"
)

// Info は /etc/os-release から読み取ったOSの情報。
type Info struct {
	ID         string `json:"id"`         // 例：ubuntu
	Name       string `json:"name"`       // 例：Ubuntu
	VersionID  string `json:"versionId"`  // 例：20.04
	PrettyName string `json:"prettyName"` // 例：Ubuntu 20.04.6 LTS
}

// Supported は診断に対応しているOSかを返す。現在は Ubuntu のみ（設計方針）。
func (i Info) Supported() bool {
	return i.ID == "ubuntu"
}

// Detect はサーバーの /etc/os-release を読んでOSを判定する。
func Detect(ctx context.Context, r remote.Runner) (Info, error) {
	out, err := r.Run(ctx, "cat /etc/os-release")
	if err != nil {
		return Info{}, fmt.Errorf("OS情報を読み取れませんでした: %w", err)
	}
	info := Parse(out)
	if info.ID == "" {
		return Info{}, fmt.Errorf("OS情報の形式が想定と違います")
	}
	return info, nil
}

// Parse は /etc/os-release の内容を解析する。
// 形式は KEY=VALUE の行の並びで、値は引用符で囲まれていることがある。
func Parse(content string) Info {
	values := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[key] = unquote(value)
	}
	return Info{
		ID:         strings.ToLower(values["ID"]),
		Name:       values["NAME"],
		VersionID:  values["VERSION_ID"],
		PrettyName: values["PRETTY_NAME"],
	}
}

func unquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		v = v[1 : len(v)-1]
	}
	return strings.ReplaceAll(v, `\"`, `"`)
}
