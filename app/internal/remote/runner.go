// Package remote は、診断対象サーバーでコマンドを実行する「係」の共通の形を定める。
//
// 各診断は Runner だけに頼るので、本番では SSH、テストでは用意した出力を返す
// FakeRunner に差し替えられる。
package remote

import (
	"context"
	"fmt"
)

// Runner は診断対象サーバーでコマンドを実行する。
// 実行するのは読み取りだけのコマンドに限る（設計方針）。
type Runner interface {
	// Run は一般ユーザーの権限でコマンドを実行し、標準出力を返す。
	Run(ctx context.Context, cmd string) (string, error)
	// RunSudo は sudo でコマンドを実行し、標準出力を返す。
	RunSudo(ctx context.Context, cmd string) (string, error)
}

// FakeRunner はテスト用の Runner。コマンドごとに決めた出力を返す。
type FakeRunner struct {
	Outputs     map[string]string // Run 用：コマンド → 出力
	SudoOutputs map[string]string // RunSudo 用：コマンド → 出力
	Calls       []string          // 呼ばれたコマンドの記録（sudo は先頭に "sudo " を付ける）
}

// Run は Outputs に登録された出力を返す。未登録ならエラー。
func (f *FakeRunner) Run(_ context.Context, cmd string) (string, error) {
	f.Calls = append(f.Calls, cmd)
	out, ok := f.Outputs[cmd]
	if !ok {
		return "", fmt.Errorf("FakeRunner: 未登録のコマンド: %q", cmd)
	}
	return out, nil
}

// RunSudo は SudoOutputs に登録された出力を返す。未登録ならエラー。
func (f *FakeRunner) RunSudo(_ context.Context, cmd string) (string, error) {
	f.Calls = append(f.Calls, "sudo "+cmd)
	out, ok := f.SudoOutputs[cmd]
	if !ok {
		return "", fmt.Errorf("FakeRunner: 未登録のsudoコマンド: %q", cmd)
	}
	return out, nil
}
