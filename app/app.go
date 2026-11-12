package main

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"app/internal/checks/ports"
	"app/internal/karte"
	"app/internal/osinfo"
	"app/internal/sshclient"
	"app/internal/store"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App は画面（React）から呼ばれる窓口。
type App struct {
	ctx      context.Context
	hostKeys sshclient.HostKeyStore

	store    *store.Store // 開けなかったときは nil（記録なしで動く）
	storeErr string

	mu     sync.Mutex
	cancel context.CancelFunc // 診察中の「中止」用
}

// ProgressEvent は診察中画面（S03）に進み具合を伝えるイベント。
// Step：connect / os、Status：running / done
const progressEvent = "checkup:progress"

type ProgressEvent struct {
	Step   string `json:"step"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func (a *App) emitProgress(step, status, detail string) {
	if a.ctx == nil {
		return
	}
	runtime.EventsEmit(a.ctx, progressEvent, ProgressEvent{Step: step, Status: status, Detail: detail})
}

// CancelCheck は診察中の処理を中止する（S03 の「中止」）。
func (a *App) CancelCheck() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cancel != nil {
		a.cancel()
	}
}

// NewApp は App を作る。
func NewApp() *App {
	// 保存先を開けるまでは、メモリ上の記録を使う
	return &App{hostKeys: sshclient.NewMemoryHostKeyStore()}
}

// appVersion は受診の記録に残すアプリのバージョン（判定の基準が変わったときの比較用）。
const appVersion = "0.2.0"

// startup はアプリ起動時に呼ばれる。保存先（SQLite）を開く。
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	path, err := store.DefaultPath()
	if err == nil {
		a.store, err = store.Open(path)
	}
	if err != nil {
		// 開けなくても診断はできるようにする。ホスト鍵はアプリを閉じるまでメモリに置く。
		a.store = nil
		a.storeErr = "記録の保存先を開けませんでした。今回の記録はアプリを閉じると消えます（" + err.Error() + "）"
		return
	}
	a.hostKeys = a.store
}

// shutdown はアプリ終了時に呼ばれる。
func (a *App) shutdown(_ context.Context) {
	if a.store != nil {
		a.store.Close()
	}
}

// ServerList は「再診の方」の一覧。
type ServerList struct {
	Servers []store.Server `json:"servers"`
	Error   string         `json:"error,omitempty"`
}

// ListServers は保存した受付票を、最近使った順に返す。
func (a *App) ListServers() ServerList {
	if a.store == nil {
		return ServerList{Servers: []store.Server{}, Error: a.storeErr}
	}
	list, err := a.store.ListServers()
	if err != nil {
		return ServerList{Servers: []store.Server{}, Error: "記録を読み込めませんでした（" + err.Error() + "）"}
	}
	if list == nil {
		list = []store.Server{}
	}
	return ServerList{Servers: list}
}

// DeleteServer は受付票と、その受診の記録を消す。
func (a *App) DeleteServer(id int64) string {
	if a.store == nil {
		return a.storeErr
	}
	if err := a.store.DeleteServer(id); err != nil {
		return "消せませんでした（" + err.Error() + "）"
	}
	return ""
}

// ReceptionForm は受付票の内容（F01・F02）。認証情報は保存しない。
type ReceptionForm struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	User          string `json:"user"`
	AuthType      string `json:"authType"` // "password" または "key"
	Password      string `json:"password"`
	KeyPath       string `json:"keyPath"`
	KeyPassphrase string `json:"keyPassphrase"`
	SudoPassword  string `json:"sudoPassword"`
	WebRoot       string `json:"webRoot"`
	Label         string `json:"label"` // 呼び名（任意）

	// TrustFingerprint は、ホスト鍵の確認画面で利用者が「接続する」を押した指紋。
	TrustFingerprint string `json:"trustFingerprint"`
}

// ConnectionResult は接続確認の結果。
//
// Status の値
//   - "ok"                 接続・OS判定・sudo確認まで成功
//   - "hostkey_unknown"    はじめてのサーバー。指紋を確認してもらう
//   - "hostkey_mismatch"   指紋が記録と違う。接続しない
//   - "unsupported_os"     Ubuntu以外
//   - "error"              接続・認証・sudoなどのエラー
//   - "canceled"           利用者が中止した
type ConnectionResult struct {
	Status      string      `json:"status"`
	Message     string      `json:"message"`
	KeyType     string      `json:"keyType,omitempty"`
	Fingerprint string      `json:"fingerprint,omitempty"`
	Expected    string      `json:"expected,omitempty"`
	OS          osinfo.Info `json:"os"`

	// 以下は Status が "ok" のときだけ入る（S04 カルテ）
	OverallGrade karte.Grade         `json:"overallGrade,omitempty"`
	GradeLabel   string              `json:"gradeLabel,omitempty"`
	Checks       []karte.CheckResult `json:"checks,omitempty"`
	FinishedAt   string              `json:"finishedAt,omitempty"`
	SaveWarning  string              `json:"saveWarning,omitempty"` // 記録を保存できなかったとき
}

// SelectKeyFile は秘密鍵ファイルを選ぶダイアログを開き、選ばれた場所を返す。
// 鍵の中身は読まない（読むのは接続するときだけ）。
func (a *App) SelectKeyFile() (string, error) {
	return runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "秘密鍵ファイルを選ぶ",
	})
}

// Diagnose は受付票の内容でサーバーに接続し、OS判定・sudoの確認のあと、各診断を行う（WBS 3.1〜4.1）。
func (a *App) Diagnose(form ReceptionForm) ConnectionResult {
	startedAt := time.Now()
	base := a.ctx
	if base == nil {
		base = context.Background()
	}
	ctx, cancel := context.WithCancel(base)
	a.mu.Lock()
	a.cancel = cancel
	a.mu.Unlock()
	defer func() {
		cancel()
		a.mu.Lock()
		a.cancel = nil
		a.mu.Unlock()
	}()

	// ① 接続（SSH接続・ホスト鍵の確認・sudoの確認）
	a.emitProgress("connect", "running", "")
	client, err := sshclient.Dial(ctx, sshclient.Config{
		Host:             form.Host,
		Port:             form.Port,
		User:             form.User,
		AuthType:         sshclient.AuthType(form.AuthType),
		Password:         form.Password,
		KeyPath:          form.KeyPath,
		KeyPassphrase:    form.KeyPassphrase,
		SudoPassword:     form.SudoPassword,
		TrustFingerprint: form.TrustFingerprint,
	}, a.hostKeys)
	if err != nil {
		if ctx.Err() != nil {
			return canceledResult()
		}
		return dialErrorResult(err)
	}
	defer client.Close()

	if err := client.CheckSudo(ctx); err != nil {
		if ctx.Err() != nil {
			return canceledResult()
		}
		return ConnectionResult{Status: "error", Message: "sudoパスワードが違うか、このユーザーにsudo権限がありません"}
	}
	a.emitProgress("connect", "done", "")

	// ② OSの確認
	a.emitProgress("os", "running", "")
	info, err := osinfo.Detect(ctx, client)
	if err != nil {
		if ctx.Err() != nil {
			return canceledResult()
		}
		return ConnectionResult{Status: "error", Message: "診断中に接続が切れたか、OS情報を読み取れませんでした。もう一度お試しください"}
	}
	if !info.Supported() {
		name := info.PrettyName
		if name == "" {
			name = info.ID
		}
		return ConnectionResult{
			Status:  "unsupported_os",
			Message: "このサーバーは " + name + " です。現在はUbuntuのみ対応しています",
			OS:      info,
		}
	}
	a.emitProgress("os", "done", info.Name+" "+info.VersionID)

	// ③ 各診断（SSH設定・不要ファイル・パッケージ更新は WBS 4.2〜4.4 で追加する）
	var checks []karte.CheckResult

	a.emitProgress(ports.CheckID, "running", "")
	portRes, err := ports.Run(ctx, client)
	if err != nil {
		if ctx.Err() != nil {
			return canceledResult()
		}
		return ConnectionResult{Status: "error", Message: "ポート診断の途中で失敗しました。もう一度お試しください（" + err.Error() + "）", OS: info}
	}
	checks = append(checks, portRes)
	a.emitProgress(ports.CheckID, "done", portRes.Summary)

	overall := karte.GradeA
	for _, c := range checks {
		overall = karte.Worse(overall, c.Grade)
	}
	// 一覧は判定の悪い順（SCREENS.md S04）
	sort.SliceStable(checks, func(i, j int) bool { return checks[i].Grade > checks[j].Grade })

	saveWarning := a.saveRecord(form, info, overall, startedAt)

	return ConnectionResult{
		Status:       "ok",
		Message:      "診断が終わりました",
		SaveWarning:  saveWarning,
		OS:           info,
		OverallGrade: overall,
		GradeLabel:   karte.GradeLabel(overall),
		Checks:       checks,
		FinishedAt:   time.Now().Format("2006/01/02 15:04"),
	}
}

// saveRecord は受付票（認証情報以外）と受診の記録を保存する。失敗しても診断結果は表示する。
func (a *App) saveRecord(form ReceptionForm, info osinfo.Info, overall karte.Grade, startedAt time.Time) string {
	if a.store == nil {
		return a.storeErr
	}
	port := form.Port
	if port == 0 {
		port = 22
	}
	keyPath := ""
	if form.AuthType == string(sshclient.AuthKey) {
		keyPath = form.KeyPath // 鍵の「場所」だけ。鍵の中身は保存しない
	}
	id, err := a.store.SaveServer(store.Server{
		Host: form.Host, Port: port, User: form.User, AuthType: form.AuthType,
		KeyPath: keyPath, WebRoot: form.WebRoot, Label: form.Label,
	})
	if err == nil {
		err = a.store.SaveDiagnosis(store.Diagnosis{
			ServerID: id, StartedAt: startedAt, FinishedAt: time.Now(), Status: "completed",
			OSName: info.Name, OSVersion: info.VersionID, OverallGrade: string(overall), AppVersion: appVersion,
		})
	}
	if err != nil {
		return "記録を保存できませんでした（" + err.Error() + "）"
	}
	return ""
}

func canceledResult() ConnectionResult {
	return ConnectionResult{Status: "canceled", Message: "診察を中止しました"}
}

func dialErrorResult(err error) ConnectionResult {
	var unknown *sshclient.UnknownHostKeyError
	var mismatch *sshclient.HostKeyMismatchError
	switch {
	case errors.As(err, &unknown):
		return ConnectionResult{
			Status:      "hostkey_unknown",
			Message:     "はじめて接続するサーバーです",
			KeyType:     unknown.KeyType,
			Fingerprint: unknown.Fingerprint,
		}
	case errors.As(err, &mismatch):
		return ConnectionResult{
			Status:      "hostkey_mismatch",
			Message:     "サーバーの指紋が記録と違います。サーバーがすり替わっている可能性があるため、接続を中止しました",
			KeyType:     mismatch.KeyType,
			Fingerprint: mismatch.Actual,
			Expected:    mismatch.Expected,
		}
	case errors.Is(err, sshclient.ErrAuth):
		return ConnectionResult{Status: "error", Message: "ユーザー名またはパスワード（鍵）が違います"}
	case errors.Is(err, sshclient.ErrKeyFile):
		return ConnectionResult{Status: "error", Message: "鍵ファイルを読み込めませんでした。場所とパスフレーズを確認してください"}
	default:
		// ErrConnect などはメッセージにパスワードを含まない
		return ConnectionResult{Status: "error", Message: err.Error() + "。IPアドレスとポート、サーバーが起動しているかを確認してください"}
	}
}
