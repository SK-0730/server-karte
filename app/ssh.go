// SSH接続とOS確認の試作（WBS 3.2・3.3）
// app/ 直下に置く。App のメソッドなので、Wailsが自動で画面から呼べるようにする
package main

import (
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

// CheckOS は受付票の内容でSSH接続し、/etc/os-release の中身を返す。
// パスワードは保存せず、この呼び出しの中だけで使う。
// 試作なので、エラーも文字列で返して画面にそのまま表示する。
func (a *App) CheckOS(host string, port int, user string, password string) string {
	cfg := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.Password(password)},
		// TODO: 試作のためホスト鍵を検証していない。
		// 本番では「初回にフィンガープリントを確認 → 保存して次回から照合」にする
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return "接続失敗: " + err.Error()
	}
	defer client.Close()

	out, err := runCommand(client, "cat /etc/os-release")
	if err != nil {
		return "コマンド失敗: " + err.Error()
	}
	return out
}

// runCommand はセッションを1つ開いてコマンドを実行し、出力を返す。
// 各診断で使い回す共通処理の原型。
func runCommand(c *ssh.Client, cmd string) (string, error) {
	s, err := c.NewSession()
	if err != nil {
		return "", err
	}
	defer s.Close()
	b, err := s.CombinedOutput(cmd)
	return string(b), err
}