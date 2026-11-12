package sshclient

import (
	"fmt"
	"sync"
	"time"
)

// HostKeyRecord は記録済みのホスト鍵（指紋）。ホスト鍵は公開情報で、認証情報ではない。
type HostKeyRecord struct {
	KeyType     string // 例：ssh-ed25519
	Fingerprint string // 例：SHA256:...
	PublicKey   string // authorized_keys 形式の公開鍵
	FirstSeenAt time.Time
	LastSeenAt  time.Time
}

// HostKeyStore はホスト鍵の記録先。本番は SQLite（DATA.md の T2 host_keys）に置き換える。
type HostKeyStore interface {
	Get(host string, port int) (HostKeyRecord, bool, error)
	Put(host string, port int, rec HostKeyRecord) error
}

// UnknownHostKeyError は、はじめて接続するサーバーのとき返る。
// 画面で指紋を確認してもらい、TrustFingerprint に入れて接続し直す。
type UnknownHostKeyError struct {
	KeyType     string
	Fingerprint string
}

func (e *UnknownHostKeyError) Error() string {
	return fmt.Sprintf("はじめて接続するサーバーです（%s %s）", e.KeyType, e.Fingerprint)
}

// HostKeyMismatchError は、記録と違うホスト鍵が提示されたとき返る。
// サーバーのすり替え（なりすまし）の可能性があるので、接続しない。
type HostKeyMismatchError struct {
	KeyType  string
	Expected string
	Actual   string
}

func (e *HostKeyMismatchError) Error() string {
	return fmt.Sprintf("サーバーの指紋が記録と違います（記録：%s、今回：%s）", e.Expected, e.Actual)
}

// MemoryHostKeyStore はメモリ上だけの HostKeyStore。テストと、SQLite 実装までのつなぎに使う。
type MemoryHostKeyStore struct {
	mu   sync.Mutex
	recs map[string]HostKeyRecord
}

// NewMemoryHostKeyStore は空の MemoryHostKeyStore を作る。
func NewMemoryHostKeyStore() *MemoryHostKeyStore {
	return &MemoryHostKeyStore{recs: map[string]HostKeyRecord{}}
}

func storeKey(host string, port int) string { return fmt.Sprintf("%s:%d", host, port) }

// Get は記録を返す。
func (s *MemoryHostKeyStore) Get(host string, port int) (HostKeyRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.recs[storeKey(host, port)]
	return rec, ok, nil
}

// Put は記録を保存（上書き）する。
func (s *MemoryHostKeyStore) Put(host string, port int, rec HostKeyRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs[storeKey(host, port)] = rec
	return nil
}
