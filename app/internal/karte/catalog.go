package karte

import "strings"

// entry は所見ごとの説明文のひな形。{port} などは Params の値で置き換える。
type entry struct {
	Title    string
	What     string
	Why      string
	HowToFix string
}

// catalog は所見コードごとの説明文（初学者向け。WBS 5.3 で磨く）。
var catalog = map[string]entry{
	// --- ポート診断 ---
	"PORT_DB_PUBLIC": {
		Title: "{service}（{port}番）が外部から届く状態です",
		What:  "データベースなどの「裏方」のソフト {service} が、{port}番ポートで外部からの接続を待ち受けています（待ち受け先：{addr}、プロセス：{process}）。",
		Why: "データベースは本来、同じサーバーの中のアプリからだけ使うものです。外部から届くと、パスワードの総当たりや既知の弱点を突かれて、" +
			"中のデータを盗まれたり消されたりするおそれがあります。インターネットに公開されたデータベースが狙われる被害は、実際に多く起きています。",
		HowToFix: "1. {service} の設定で、待ち受け先を 127.0.0.1（このサーバーの中だけ）にします。\n" +
			"2. Docker で動かしている場合は、公開の指定を「-p 127.0.0.1:{port}:{port}」のように 127.0.0.1 付きにします。\n" +
			"3. 直したら、もう一度診断して、この項目が消えたか確かめます。",
	},
	"PORT_DOCKER_API_PUBLIC": {
		Title: "Docker の操作窓口（{port}番）が外部から届く状態です",
		What:  "Docker を操作するための窓口（Docker API）が、{port}番ポートで外部からの接続を待ち受けています（待ち受け先：{addr}）。",
		Why: "この窓口に届く人は、パスワードなしでコンテナを自由に作れます。サーバーを乗っ取られたのと同じ状態で、" +
			"仮想通貨の採掘などに悪用される被害が知られています。",
		HowToFix: "1. Docker の設定（/etc/docker/daemon.json や起動オプション）から「tcp://0.0.0.0:{port}」の指定を外します。\n" +
			"2. 外から操作する必要があるなら、SSH 経由で使います。\n" +
			"3. 直したら、もう一度診断して確かめます。",
	},
	"PORT_PLAINTEXT_PUBLIC": {
		Title: "暗号化されない {service}（{port}番）が外部から届く状態です",
		What:  "{service} が {port}番ポートで外部からの接続を待ち受けています（待ち受け先：{addr}、プロセス：{process}）。",
		Why:   "{service} は通信を暗号化しないため、パスワードなどが途中で盗み見られるおそれがあります。今は使う必要がほとんどない古い仕組みです。",
		HowToFix: "1. 使っていなければ、{service} を止めて、自動で起動しないようにします。\n" +
			"2. 代わりに暗号化される仕組み（SSH、SFTP など）を使います。\n" +
			"3. 直したら、もう一度診断して確かめます。",
	},
	"PORT_DEV_PUBLIC": {
		Title: "開発用らしきポート（{port}番）が外部から届く状態です",
		What:  "{port}番ポートで、{process} が外部からの接続を待ち受けています（待ち受け先：{addr}）。このポートは、開発中のアプリでよく使われる番号です。",
		Why: "開発用のサーバーは、エラーの詳細を表示したり、守りが甘い設定のまま動いたりすることが多く、外部に見せる前提で作られていません。" +
			"試しに動かしたまま、公開してしまう例がよくあります。",
		HowToFix: "1. 外部に公開するつもりがなければ、待ち受け先を 127.0.0.1 にするか、止めます。\n" +
			"2. 公開するなら、本番用の設定（Webサーバーの裏に置くなど）にします。\n" +
			"3. 直したら、もう一度診断して確かめます。",
	},
	"PORT_UNKNOWN_PUBLIC": {
		Title: "用途を確かめたいポート（{port}番）が外部から届く状態です",
		What:  "{port}番ポート（{proto}）で、{process} が外部からの接続を待ち受けています（待ち受け先：{addr}）。",
		Why:   "何のために開いているか分からないポートは、知らないうちに弱点になります。「使っていないのに開いている」が、いちばん危ない状態です。",
		HowToFix: "1. 表示されたプロセス名を手がかりに、何のソフトか調べます。\n" +
			"2. 使っていなければ止めます。使っているなら、外部から届く必要があるか考え、不要なら待ち受け先を 127.0.0.1 にします。\n" +
			"3. 直したら、もう一度診断して確かめます。",
	},
	"PORT_EXPECTED_PUBLIC": {
		Title:    "{service}（{port}番）が外部から届く状態です",
		What:     "{service} が {port}番ポートで外部からの接続を待ち受けています（待ち受け先：{addr}、プロセス：{process}）。",
		Why:      "{service} は外部から使うためのものなので、開いていること自体は問題ありません。中身の設定が安全かどうかは、ほかの診断で確かめます。",
		HowToFix: "使っていなければ止めましょう。使っている場合は、このままで大丈夫です。",
	},
	"FIREWALL_INACTIVE": {
		Title: "ファイアウォール（ufw）が無効です",
		What:  "ufw の状態が「inactive（無効）」でした。外部から届くポートを、ファイアウォールで絞っていない状態です。",
		Why:   "ファイアウォールは、開けるつもりのないポートへの接続を入口で止める「門番」です。無効だと、設定ミスで開いたポートがそのまま外部から届きます。",
		HowToFix: "1. 先に SSH を許可します：sudo ufw allow OpenSSH\n" +
			"   （これを忘れると、有効にした瞬間に自分も締め出されます）\n" +
			"2. 公開するポートだけ許可します（例：sudo ufw allow 80/tcp）。\n" +
			"3. 有効にします：sudo ufw enable\n" +
			"4. もう一度診断して確かめます。",
	},
	"FIREWALL_UNKNOWN": {
		Title: "ファイアウォール（ufw）の状態を確かめられませんでした",
		What:  "ufw の状態を読み取れませんでした。ufw が入っていないか、別のファイアウォールを使っている可能性があります。",
		Why:   "ファイアウォールの状態が分からないと、外部から届くポートが本当に守られているか判断できません。",
		HowToFix: "1. sudo ufw status を実行して状態を確かめます。\n" +
			"2. 入っていなければ、sudo apt install ufw で入れて有効にします（SSH の許可を先に）。",
	},
	"DOCKER_BYPASSES_UFW": {
		Title: "Docker で公開したポートは、ufw の設定をすり抜けます",
		What:  "Docker が公開しているポートがあります（{ports}）。",
		Why: "Docker でポートを公開すると、通信は ufw の設定より先に Docker の決まりで処理されます。そのため ufw で「拒否」にしていても、" +
			"外部から届いてしまいます（Docker 公式ドキュメントにも書かれている、初学者がつまずきやすい点です）。",
		HowToFix: "1. 外部に公開する必要がないコンテナは、「-p 127.0.0.1:ポート:ポート」のように 127.0.0.1 付きで公開します。\n" +
			"2. docker-compose なら ports: に \"127.0.0.1:ポート:ポート\" と書きます。\n" +
			"3. 直したら、もう一度診断して確かめます。",
	},
	"PORT_NONE_PUBLIC": {
		Title:    "外部から届くポートはありませんでした",
		What:     "外部からの接続を待ち受けているポートは見つかりませんでした。",
		Why:      "外部から届く入口がなければ、外からの攻撃を受ける心配は小さくなります。",
		HowToFix: "このままで大丈夫です。",
	},
}

// Describe は所見に説明文を埋める。
func Describe(f Finding) Finding {
	e, ok := catalog[f.Code]
	if !ok {
		f.Title = f.Code
		return f
	}
	f.Title = fill(e.Title, f.Params)
	f.What = fill(e.What, f.Params)
	f.Why = fill(e.Why, f.Params)
	f.HowToFix = fill(e.HowToFix, f.Params)
	return f
}

func fill(s string, params map[string]string) string {
	for k, v := range params {
		s = strings.ReplaceAll(s, "{"+k+"}", v)
	}
	return s
}
