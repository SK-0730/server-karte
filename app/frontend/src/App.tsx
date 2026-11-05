import {useState} from 'react';
import './App.css';
import {CheckOS} from "../wailsjs/go/main/App";

// SSH接続テスト用の仮画面（WBS 3.2・3.3 の試作）
// 本番の受付票画面（3.1）を作るときに置き換える
function App() {
    const [host, setHost] = useState("192.168.56.104");
    const [port, setPort] = useState("22");
    const [user, setUser] = useState("");
    const [password, setPassword] = useState("");
    const [result, setResult] = useState("接続先を入力して「テスト接続」を押してください");
    const [busy, setBusy] = useState(false);

    async function check() {
        setBusy(true);
        setResult("接続中…");
        try {
            setResult(await CheckOS(host, Number(port), user, password));
        } catch (e) {
            setResult("想定外のエラー: " + String(e));
        } finally {
            setPassword(""); // パスワードは使い終わったら消す
            setBusy(false);
        }
    }

    return (
        <div id="App" style={{padding: 24, textAlign: "left"}}>
            <h2>サーバーカルテ 接続テスト（仮）</h2>
            <div style={{display: "grid", gap: 8, maxWidth: 360}}>
                <label>ホスト <input value={host} onChange={e => setHost(e.target.value)}/></label>
                <label>ポート <input value={port} onChange={e => setPort(e.target.value)}/></label>
                <label>ユーザー名 <input value={user} onChange={e => setUser(e.target.value)} autoComplete="off"/></label>
                <label>パスワード <input type="password" value={password} onChange={e => setPassword(e.target.value)}/></label>
                <button onClick={check} disabled={busy}>テスト接続</button>
            </div>
            <pre style={{marginTop: 16, whiteSpace: "pre-wrap"}}>{result}</pre>
        </div>
    )
}

export default App
