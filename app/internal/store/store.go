// Package store は利用者のPC内の SQLite に記録を保存する（docs/DATA.md）。
//
// 保存するもの：受付票（認証情報以外）、ホスト鍵、受診の記録（総合判定）
// 保存しないもの：SSHのパスワード・秘密鍵・パスフレーズ、sudoパスワード（設計方針）
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"app/internal/sshclient"

	_ "modernc.org/sqlite" // Cを使わない SQLite（Windows向けにそのままビルドできる）
)

// Store は SQLite の記録。
type Store struct {
	db *sql.DB
}

// DefaultPath は保存先を返す。Windows では %APPDATA%\server-karte\karte.db。
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "server-karte", "karte.db"), nil
}

// Open は保存先を開く（なければ作る）。
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("保存先のフォルダを作れませんでした: %w", err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // アプリは1人で使うので、書き込みがぶつからないよう1本にする
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close は保存先を閉じる。
func (s *Store) Close() error { return s.db.Close() }

const schemaVersion = 1

// テーブル定義（docs/DATA.md）。
// ホスト鍵はユーザー名に関係なくサーバー（host・port）ごとに1つなので、servers とは分けて host・port で持つ。
const schema = `
CREATE TABLE IF NOT EXISTS servers (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	host       TEXT    NOT NULL,
	port       INTEGER NOT NULL DEFAULT 22,
	username   TEXT    NOT NULL,
	auth_type  TEXT    NOT NULL CHECK (auth_type IN ('password', 'key')),
	key_path   TEXT,
	web_root   TEXT,
	label      TEXT,
	created_at TEXT    NOT NULL,
	updated_at TEXT    NOT NULL,
	UNIQUE (host, port, username)
);

CREATE TABLE IF NOT EXISTS host_keys (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	host          TEXT    NOT NULL,
	port          INTEGER NOT NULL,
	key_type      TEXT    NOT NULL,
	fingerprint   TEXT    NOT NULL,
	public_key    TEXT    NOT NULL,
	first_seen_at TEXT    NOT NULL,
	last_seen_at  TEXT    NOT NULL,
	UNIQUE (host, port)
);

CREATE TABLE IF NOT EXISTS diagnoses (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	server_id     INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
	started_at    TEXT    NOT NULL,
	finished_at   TEXT,
	status        TEXT    NOT NULL CHECK (status IN ('completed', 'aborted', 'failed')),
	os_name       TEXT,
	os_version    TEXT,
	overall_grade TEXT,
	app_version   TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_diagnoses_server ON diagnoses(server_id, finished_at);
`

func (s *Store) migrate() error {
	var v int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return err
	}
	if v >= schemaVersion {
		return nil
	}
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("保存先の準備に失敗しました: %w", err)
	}
	_, err := s.db.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion))
	return err
}

// 日時は文字列で持つ（SQLiteには日時型がないため）。並べ替えできるよう、UTC・桁数固定にする。
const timeLayout = "2006-01-02T15:04:05.000000000Z07:00"

func now() string { return time.Now().UTC().Format(timeLayout) }

func formatTime(t time.Time) string { return t.UTC().Format(timeLayout) }

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

// --- ホスト鍵（sshclient.HostKeyStore を満たす） ---

var _ sshclient.HostKeyStore = (*Store)(nil)

// Get は記録済みのホスト鍵を返す。
func (s *Store) Get(host string, port int) (sshclient.HostKeyRecord, bool, error) {
	var rec sshclient.HostKeyRecord
	var first, last string
	err := s.db.QueryRow(`SELECT key_type, fingerprint, public_key, first_seen_at, last_seen_at
		FROM host_keys WHERE host = ? AND port = ?`, host, port).
		Scan(&rec.KeyType, &rec.Fingerprint, &rec.PublicKey, &first, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return rec, false, nil
	}
	if err != nil {
		return rec, false, err
	}
	rec.FirstSeenAt, rec.LastSeenAt = parseTime(first), parseTime(last)
	return rec, true, nil
}

// Put はホスト鍵を記録する（あれば上書き）。
func (s *Store) Put(host string, port int, rec sshclient.HostKeyRecord) error {
	_, err := s.db.Exec(`INSERT INTO host_keys (host, port, key_type, fingerprint, public_key, first_seen_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (host, port) DO UPDATE SET
			key_type = excluded.key_type, fingerprint = excluded.fingerprint,
			public_key = excluded.public_key, last_seen_at = excluded.last_seen_at`,
		host, port, rec.KeyType, rec.Fingerprint, rec.PublicKey,
		formatTime(rec.FirstSeenAt), formatTime(rec.LastSeenAt))
	return err
}

// --- 受付票 ---

// Server は保存する受付票の内容。認証情報は含めない。
type Server struct {
	ID       int64  `json:"id"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	AuthType string `json:"authType"`
	KeyPath  string `json:"keyPath"`
	WebRoot  string `json:"webRoot"`
	Label    string `json:"label"`

	// 最後の受診（なければ空）
	LastDiagnosedAt string `json:"lastDiagnosedAt"`
	LastGrade       string `json:"lastGrade"`
}

// SaveServer は受付票を保存する。同じ接続先・ユーザー名なら上書きし、その id を返す。
func (s *Store) SaveServer(sv Server) (int64, error) {
	t := now()
	var id int64
	err := s.db.QueryRow(`INSERT INTO servers (host, port, username, auth_type, key_path, web_root, label, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (host, port, username) DO UPDATE SET
			auth_type = excluded.auth_type, key_path = excluded.key_path, web_root = excluded.web_root,
			label = excluded.label, updated_at = excluded.updated_at
		RETURNING id`,
		sv.Host, sv.Port, sv.User, sv.AuthType, nullable(sv.KeyPath), nullable(sv.WebRoot), nullable(sv.Label), t, t).Scan(&id)
	return id, err
}

// ListServers は保存した受付票を、最近使った順に返す（再診の方）。
// 受診のたびに受付票も保存し直すので、updated_at が「最後に使った日時」になる。
func (s *Store) ListServers() ([]Server, error) {
	rows, err := s.db.Query(`
		SELECT s.id, s.host, s.port, s.username, s.auth_type,
		       COALESCE(s.key_path, ''), COALESCE(s.web_root, ''), COALESCE(s.label, ''),
		       COALESCE(d.finished_at, ''), COALESCE(d.overall_grade, '')
		FROM servers s
		LEFT JOIN diagnoses d ON d.id = (
			SELECT id FROM diagnoses WHERE server_id = s.id AND status = 'completed'
			ORDER BY finished_at DESC LIMIT 1)
		ORDER BY s.updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Server
	for rows.Next() {
		var sv Server
		if err := rows.Scan(&sv.ID, &sv.Host, &sv.Port, &sv.User, &sv.AuthType,
			&sv.KeyPath, &sv.WebRoot, &sv.Label, &sv.LastDiagnosedAt, &sv.LastGrade); err != nil {
			return nil, err
		}
		list = append(list, sv)
	}
	return list, rows.Err()
}

// DeleteServer は受付票と、その受診の記録を消す。ホスト鍵は残す（同じサーバーにまた接続したとき照合できるように）。
func (s *Store) DeleteServer(id int64) error {
	_, err := s.db.Exec(`DELETE FROM servers WHERE id = ?`, id)
	return err
}

// --- 受診の記録 ---

// Diagnosis は1回の受診の記録（総合判定まで。各診断の詳細の保存は WBS 7.1）。
type Diagnosis struct {
	ServerID     int64
	StartedAt    time.Time
	FinishedAt   time.Time
	Status       string // completed / aborted / failed
	OSName       string
	OSVersion    string
	OverallGrade string
	AppVersion   string
}

// SaveDiagnosis は受診の記録を保存する。
func (s *Store) SaveDiagnosis(d Diagnosis) error {
	var finished any
	if !d.FinishedAt.IsZero() {
		finished = formatTime(d.FinishedAt)
	}
	_, err := s.db.Exec(`INSERT INTO diagnoses (server_id, started_at, finished_at, status, os_name, os_version, overall_grade, app_version)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		d.ServerID, formatTime(d.StartedAt), finished, d.Status,
		nullable(d.OSName), nullable(d.OSVersion), nullable(d.OverallGrade), d.AppVersion)
	return err
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
