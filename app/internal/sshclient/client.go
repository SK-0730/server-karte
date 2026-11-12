// Package sshclient は診断対象サーバーへのSSH接続とコマンド実行を受け持つ（F03 / WBS 3.2）。
//
// 守ること（設計方針）
//   - パスワード・鍵・sudoパスワードは保存しない。ログやエラー文にも出さない
//   - sudoパスワードはコマンドの引数に入れず、標準入力で渡す（引数だとサーバーのプロセス一覧から見える）
//   - ホスト鍵は必ず確認する（はじめては指紋を利用者に確認、記録と違えば接続しない）
package sshclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// AuthType はログイン方法。
type AuthType string

const (
	AuthPassword AuthType = "password"
	AuthKey      AuthType = "key"
)

// Config は接続に必要な情報（受付票の内容）。
type Config struct {
	Host          string
	Port          int
	User          string
	AuthType      AuthType
	Password      string // AuthPassword のとき
	KeyPath       string // AuthKey のとき：秘密鍵ファイルの場所
	KeyPassphrase string // AuthKey のとき：鍵にパスフレーズがあれば
	SudoPassword  string
	Timeout       time.Duration // 0 なら 10 秒

	// TrustFingerprint は、利用者が画面で確認して「接続する」を押した指紋。
	// はじめてのサーバーで、提示された指紋とこれが一致したときだけ記録して接続する。
	TrustFingerprint string
}

// 画面でエラーの種類を見分けるためのエラー。
var (
	ErrConnect    = errors.New("サーバーに接続できませんでした")
	ErrAuth       = errors.New("ユーザー名またはパスワード（鍵）が違います")
	ErrKeyFile    = errors.New("鍵ファイルを読み込めませんでした")
	ErrSudo       = errors.New("sudoを実行できませんでした")
	ErrDisconnect = errors.New("接続が切れました")
)

// Client は接続済みのSSHクライアント。remote.Runner として使える。
type Client struct {
	conn         *ssh.Client
	sudoPassword string
}

// Dial はサーバーに接続する。ホスト鍵の確認に HostKeyStore を使う。
//
// はじめてのサーバーでは *UnknownHostKeyError、記録と指紋が違えば *HostKeyMismatchError を返す。
func Dial(ctx context.Context, cfg Config, store HostKeyStore) (*Client, error) {
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	auth, err := authMethods(cfg)
	if err != nil {
		return nil, err
	}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))

	stored, hasStored, err := store.Get(cfg.Host, cfg.Port)
	if err != nil {
		return nil, fmt.Errorf("ホスト鍵の記録を読めませんでした: %w", err)
	}

	// ホスト鍵の確認で起きたエラーは、ここに取っておいて後で返す
	// （ssh ライブラリの包み方に左右されないようにするため）。
	var hostKeyErr error
	callback := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		now := time.Now()
		switch {
		case hasStored && stored.Fingerprint == fp:
			stored.LastSeenAt = now
			return store.Put(cfg.Host, cfg.Port, stored)
		case hasStored:
			hostKeyErr = &HostKeyMismatchError{KeyType: key.Type(), Expected: stored.Fingerprint, Actual: fp}
			return hostKeyErr
		case cfg.TrustFingerprint != "" && cfg.TrustFingerprint == fp:
			return store.Put(cfg.Host, cfg.Port, HostKeyRecord{
				KeyType:     key.Type(),
				Fingerprint: fp,
				PublicKey:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))),
				FirstSeenAt: now,
				LastSeenAt:  now,
			})
		default:
			hostKeyErr = &UnknownHostKeyError{KeyType: key.Type(), Fingerprint: fp}
			return hostKeyErr
		}
	}

	sshCfg := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            auth,
		HostKeyCallback: callback,
		Timeout:         cfg.Timeout,
	}
	// 記録済みの鍵の種類を指定する。サーバーが複数の鍵を持っていても、
	// 毎回同じ種類の鍵で比べられるようにするため（OpenSSH と同じ考え方）。
	if hasStored {
		sshCfg.HostKeyAlgorithms = hostKeyAlgorithmsFor(stored.KeyType)
	}

	dialer := net.Dialer{Timeout: cfg.Timeout}
	netConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("%w（%s）", ErrConnect, describeNetErr(err))
	}
	_ = netConn.SetDeadline(time.Now().Add(cfg.Timeout))

	c, chans, reqs, err := ssh.NewClientConn(netConn, addr, sshCfg)
	if err != nil {
		netConn.Close()
		if hostKeyErr != nil {
			return nil, hostKeyErr
		}
		if strings.Contains(err.Error(), "unable to authenticate") {
			return nil, ErrAuth
		}
		return nil, fmt.Errorf("%w（%s）", ErrConnect, describeNetErr(err))
	}
	_ = netConn.SetDeadline(time.Time{})

	return &Client{conn: ssh.NewClient(c, chans, reqs), sudoPassword: cfg.SudoPassword}, nil
}

// Run はコマンドを実行し、標準出力を返す。
func (c *Client) Run(ctx context.Context, cmd string) (string, error) {
	stdout, _, err := c.exec(ctx, cmd, "")
	return stdout, err
}

// RunSudo は sudo でコマンドを実行する。パスワードは標準入力で渡す。
//
//	-S  パスワードを標準入力から読む
//	-k  キャッシュを使わず、毎回パスワードを確かめる
//	-p '' 入力を促す文を出さない（出力に混ざらないように）
func (c *Client) RunSudo(ctx context.Context, cmd string) (string, error) {
	stdout, stderr, err := c.exec(ctx, sudoCommand(cmd), c.sudoPassword+"\n")
	if err != nil && isSudoFailure(stderr) {
		return "", ErrSudo
	}
	return stdout, err
}

// CheckSudo は sudo が使えるか（パスワードが正しく、権限があるか）を確かめる。
func (c *Client) CheckSudo(ctx context.Context) error {
	if _, err := c.RunSudo(ctx, "true"); err != nil {
		if errors.Is(err, ErrSudo) {
			return ErrSudo
		}
		return fmt.Errorf("%w: %v", ErrSudo, err)
	}
	return nil
}

// Close は接続を閉じ、メモリ上の sudo パスワードへの参照を消す。
func (c *Client) Close() error {
	c.sudoPassword = ""
	return c.conn.Close()
}

func sudoCommand(cmd string) string {
	return "sudo -S -k -p '' " + cmd
}

func (c *Client) exec(ctx context.Context, cmd, stdin string) (string, string, error) {
	sess, err := c.conn.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("%w: %v", ErrDisconnect, err)
	}
	defer sess.Close()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr
	if stdin != "" {
		sess.Stdin = strings.NewReader(stdin)
	}

	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()

	select {
	case <-ctx.Done():
		sess.Close()
		return "", "", ctx.Err()
	case err := <-done:
		if err != nil {
			var exitErr *ssh.ExitError
			if errors.As(err, &exitErr) {
				return stdout.String(), stderr.String(),
					fmt.Errorf("コマンドが失敗しました（終了コード %d）", exitErr.ExitStatus())
			}
			return stdout.String(), stderr.String(), fmt.Errorf("%w: %v", ErrDisconnect, err)
		}
		return stdout.String(), stderr.String(), nil
	}
}

func authMethods(cfg Config) ([]ssh.AuthMethod, error) {
	switch cfg.AuthType {
	case AuthPassword:
		pw := cfg.Password
		// Ubuntu ではパスワードを keyboard-interactive で聞かれることもあるので、両方用意する。
		return []ssh.AuthMethod{
			ssh.Password(pw),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = pw
				}
				return answers, nil
			}),
		}, nil
	case AuthKey:
		pem, err := os.ReadFile(cfg.KeyPath)
		if err != nil {
			return nil, ErrKeyFile
		}
		signer, err := ssh.ParsePrivateKey(pem)
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(pem, []byte(cfg.KeyPassphrase))
		}
		if err != nil {
			return nil, ErrKeyFile
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	default:
		return nil, fmt.Errorf("ログイン方法が正しくありません: %q", cfg.AuthType)
	}
}

func isSudoFailure(stderr string) bool {
	s := strings.ToLower(stderr)
	return strings.Contains(s, "incorrect password") ||
		strings.Contains(s, "sorry, try again") ||
		strings.Contains(s, "not in the sudoers") ||
		strings.Contains(s, "is not allowed to run sudo") ||
		strings.Contains(s, "a password is required")
}

func describeNetErr(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "時間切れ"
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "connection refused"):
		return "接続を拒否されました。ポート番号とSSHが起動しているかを確認してください"
	case strings.Contains(s, "no such host"):
		return "ホスト名が見つかりません"
	case strings.Contains(s, "network is unreachable"), strings.Contains(s, "no route to host"):
		return "ネットワークに届きません"
	default:
		return "通信エラー"
	}
}

// hostKeyAlgorithmsFor は鍵の種類から、使う署名アルゴリズムの一覧を返す。
func hostKeyAlgorithmsFor(keyType string) []string {
	if keyType == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	return []string{keyType}
}
