package sshclient

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// テスト用のSSHサーバー。patient01 がなくても接続・認証・sudo・ホスト鍵の確認を試せる。
type testServer struct {
	addr     string
	host     string
	port     int
	hostKey  ssh.Signer
	user     string
	password string
	sudoPass string
	outputs  map[string]string // コマンド → 出力
	lastCmds []string
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	s := &testServer{
		hostKey:  signer,
		user:     "dev",
		password: "secret",
		sudoPass: "sudopass",
		outputs: map[string]string{
			"cat /etc/os-release": "ID=ubuntu\nVERSION_ID=\"20.04\"\n",
			"true":                "",
		},
	}

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if c.User() == s.user && string(pw) == s.password {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s.addr = ln.Addr().String()
	host, portStr, _ := net.SplitHostPort(s.addr)
	s.host = host
	s.port, _ = strconv.Atoi(portStr)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn, cfg)
		}
	}()
	return s
}

func (s *testServer) serve(conn net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		conn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go s.handleSession(ch, chReqs)
	}
}

func (s *testServer) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		if req.Type != "exec" {
			req.Reply(false, nil)
			continue
		}
		var payload struct{ Command string }
		ssh.Unmarshal(req.Payload, &payload)
		req.Reply(true, nil)
		s.lastCmds = append(s.lastCmds, payload.Command)

		cmd := payload.Command
		if rest, ok := strings.CutPrefix(cmd, "sudo -S -k -p '' "); ok {
			line, _ := bufio.NewReader(ch).ReadString('\n')
			if strings.TrimSuffix(line, "\n") != s.sudoPass {
				ch.Stderr().Write([]byte("Sorry, try again.\nsudo: 1 incorrect password attempt\n"))
				sendExit(ch, 1)
				return
			}
			cmd = rest
		}
		out, ok := s.outputs[cmd]
		if !ok {
			ch.Stderr().Write([]byte("command not found\n"))
			sendExit(ch, 127)
			return
		}
		ch.Write([]byte(out))
		sendExit(ch, 0)
		return
	}
}

func sendExit(ch ssh.Channel, code uint32) {
	ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
}

func (s *testServer) config() Config {
	return Config{
		Host: s.host, Port: s.port, User: s.user,
		AuthType: AuthPassword, Password: s.password, SudoPassword: s.sudoPass,
		Timeout: 5 * time.Second,
	}
}

func (s *testServer) fingerprint() string { return ssh.FingerprintSHA256(s.hostKey.PublicKey()) }

func TestFirstConnectionAsksToConfirmHostKey(t *testing.T) {
	s := newTestServer(t)
	store := NewMemoryHostKeyStore()

	_, err := Dial(context.Background(), s.config(), store)
	var unknown *UnknownHostKeyError
	if !errors.As(err, &unknown) {
		t.Fatalf("はじめての接続は UnknownHostKeyError のはず: %v", err)
	}
	if unknown.Fingerprint != s.fingerprint() {
		t.Fatalf("指紋 = %s, want %s", unknown.Fingerprint, s.fingerprint())
	}
	if _, ok, _ := store.Get(s.host, s.port); ok {
		t.Fatal("確認前に記録してはいけない")
	}
}

func TestConfirmedHostKeyIsRecordedAndReused(t *testing.T) {
	s := newTestServer(t)
	store := NewMemoryHostKeyStore()

	cfg := s.config()
	cfg.TrustFingerprint = s.fingerprint()
	c, err := Dial(context.Background(), cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()

	rec, ok, _ := store.Get(s.host, s.port)
	if !ok || rec.Fingerprint != s.fingerprint() || rec.KeyType != ssh.KeyAlgoED25519 {
		t.Fatalf("記録が正しくない: %+v", rec)
	}

	// 2回目は確認なしで接続できる
	c, err = Dial(context.Background(), s.config(), store)
	if err != nil {
		t.Fatalf("2回目の接続に失敗: %v", err)
	}
	c.Close()
}

func TestWrongTrustFingerprintIsRejected(t *testing.T) {
	s := newTestServer(t)
	cfg := s.config()
	cfg.TrustFingerprint = "SHA256:somethingelse"
	_, err := Dial(context.Background(), cfg, NewMemoryHostKeyStore())
	var unknown *UnknownHostKeyError
	if !errors.As(err, &unknown) {
		t.Fatalf("確認した指紋と違えば接続しないはず: %v", err)
	}
}

func TestHostKeyMismatchStopsConnection(t *testing.T) {
	s := newTestServer(t)
	store := NewMemoryHostKeyStore()
	store.Put(s.host, s.port, HostKeyRecord{KeyType: ssh.KeyAlgoED25519, Fingerprint: "SHA256:old"})

	_, err := Dial(context.Background(), s.config(), store)
	var mismatch *HostKeyMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("指紋が違えば HostKeyMismatchError のはず: %v", err)
	}
	if mismatch.Actual != s.fingerprint() {
		t.Fatalf("Actual = %s", mismatch.Actual)
	}
}

func trustedClient(t *testing.T, s *testServer, mutate func(*Config)) (*Client, error) {
	t.Helper()
	cfg := s.config()
	cfg.TrustFingerprint = s.fingerprint()
	if mutate != nil {
		mutate(&cfg)
	}
	return Dial(context.Background(), cfg, NewMemoryHostKeyStore())
}

func TestWrongPassword(t *testing.T) {
	s := newTestServer(t)
	_, err := trustedClient(t, s, func(c *Config) { c.Password = "wrong" })
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("ErrAuth のはず: %v", err)
	}
}

func TestConnectionRefused(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close() // 誰も待ち受けていないポート
	_, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	_, err := Dial(context.Background(), Config{
		Host: "127.0.0.1", Port: port, User: "dev", AuthType: AuthPassword, Password: "x",
		Timeout: 2 * time.Second,
	}, NewMemoryHostKeyStore())
	if !errors.Is(err, ErrConnect) {
		t.Fatalf("ErrConnect のはず: %v", err)
	}
}

func TestRunAndSudo(t *testing.T) {
	s := newTestServer(t)
	c, err := trustedClient(t, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	out, err := c.Run(context.Background(), "cat /etc/os-release")
	if err != nil || !strings.Contains(out, "ID=ubuntu") {
		t.Fatalf("Run: out=%q err=%v", out, err)
	}

	if err := c.CheckSudo(context.Background()); err != nil {
		t.Fatalf("CheckSudo: %v", err)
	}

	// sudo パスワードがコマンドの引数に入っていないこと
	for _, cmd := range s.lastCmds {
		if strings.Contains(cmd, s.sudoPass) {
			t.Fatalf("sudoパスワードがコマンドに含まれている: %q", cmd)
		}
	}
}

func TestWrongSudoPassword(t *testing.T) {
	s := newTestServer(t)
	c, err := trustedClient(t, s, func(c *Config) { c.SudoPassword = "wrong" })
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.CheckSudo(context.Background()); !errors.Is(err, ErrSudo) {
		t.Fatalf("ErrSudo のはず: %v", err)
	}
}

func TestErrorsDoNotLeakSecrets(t *testing.T) {
	s := newTestServer(t)
	_, err := trustedClient(t, s, func(c *Config) { c.Password = "MySecretPw123" })
	if err == nil || strings.Contains(err.Error(), "MySecretPw123") {
		t.Fatalf("エラー文にパスワードが含まれてはいけない: %v", err)
	}
}
