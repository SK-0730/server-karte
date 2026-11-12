package store

import (
	"path/filepath"
	"testing"
	"time"

	"app/internal/sshclient"
)

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sub", "karte.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func TestHostKeyRoundTrip(t *testing.T) {
	s, path := openTemp(t)
	if _, ok, err := s.Get("192.168.56.104", 22); ok || err != nil {
		t.Fatalf("空のはず: ok=%v err=%v", ok, err)
	}
	now := time.Now().Truncate(time.Second)
	rec := sshclient.HostKeyRecord{KeyType: "ssh-ed25519", Fingerprint: "SHA256:abc", PublicKey: "ssh-ed25519 AAAA", FirstSeenAt: now, LastSeenAt: now}
	if err := s.Put("192.168.56.104", 22, rec); err != nil {
		t.Fatal(err)
	}

	// アプリを閉じて開き直しても残っている（今回いちばん大事な点）
	s.Close()
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, ok, err := s2.Get("192.168.56.104", 22)
	if err != nil || !ok || got.Fingerprint != "SHA256:abc" || !got.FirstSeenAt.Equal(now) {
		t.Fatalf("開き直したあと: %+v ok=%v err=%v", got, ok, err)
	}

	// 別のポートは別のサーバー扱い
	if _, ok, _ := s2.Get("192.168.56.104", 2222); ok {
		t.Fatal("ポートが違えば別の記録")
	}

	// 上書き（初回日時は残る）
	later := now.Add(time.Hour)
	rec2 := rec
	rec2.LastSeenAt = later
	rec2.FirstSeenAt = later
	s2.Put("192.168.56.104", 22, rec2)
	got, _, _ = s2.Get("192.168.56.104", 22)
	if !got.FirstSeenAt.Equal(now) || !got.LastSeenAt.Equal(later) {
		t.Fatalf("初回日時は変えない: %+v", got)
	}
}

func TestServersAndDiagnoses(t *testing.T) {
	s, _ := openTemp(t)
	id1, err := s.SaveServer(Server{Host: "192.168.56.104", Port: 22, User: "dev", AuthType: "password", Label: "検証用サーバー"})
	if err != nil {
		t.Fatal(err)
	}
	id2, _ := s.SaveServer(Server{Host: "192.168.1.31", Port: 22, User: "pi", AuthType: "key", KeyPath: `C:\Users\me\.ssh\id_ed25519`})

	// 同じ接続先・ユーザー名なら上書き（行は増えない）
	again, _ := s.SaveServer(Server{Host: "192.168.56.104", Port: 22, User: "dev", AuthType: "password", Label: "患者1"})
	if again != id1 {
		t.Fatalf("同じ受付票は同じ id: %d != %d", again, id1)
	}

	start := time.Now().Add(-time.Minute)
	if err := s.SaveDiagnosis(Diagnosis{ServerID: id1, StartedAt: start, FinishedAt: start.Add(30 * time.Second),
		Status: "completed", OSName: "Ubuntu", OSVersion: "20.04", OverallGrade: "E", AppVersion: "test"}); err != nil {
		t.Fatal(err)
	}

	list, err := s.ListServers()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("2件のはず: %+v", list)
	}
	if list[0].ID != id1 || list[0].Label != "患者1" || list[0].LastGrade != "E" || list[0].LastDiagnosedAt == "" {
		t.Errorf("受診したサーバーが先頭・最新の判定付き: %+v", list[0])
	}
	if list[1].ID != id2 || list[1].LastGrade != "" || list[1].KeyPath == "" {
		t.Errorf("未受診のサーバー: %+v", list[1])
	}

	if err := s.DeleteServer(id1); err != nil {
		t.Fatal(err)
	}
	list, _ = s.ListServers()
	if len(list) != 1 {
		t.Fatalf("消したあと1件: %+v", list)
	}
	var n int
	s.db.QueryRow("SELECT COUNT(*) FROM diagnoses").Scan(&n)
	if n != 0 {
		t.Errorf("受診の記録も一緒に消えるはず: %d", n)
	}
}

func TestNoSecretColumns(t *testing.T) {
	s, _ := openTemp(t)
	rows, err := s.db.Query(`SELECT name FROM pragma_table_info('servers')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		rows.Scan(&name)
		switch name {
		case "password", "sudo_password", "passphrase", "private_key":
			t.Errorf("認証情報の列があってはいけない: %s", name)
		}
	}
}
