// S01 受付票（docs/SCREENS.md）
// 見た目はデザイン案「E 受付窓口型（改）」に合わせる。
import {FormEvent} from 'react';
import {SelectKeyFile} from '../../wailsjs/go/main/App';

export type AuthType = 'password' | 'key';

export type Form = {
    host: string;
    port: string;
    user: string;
    authType: AuthType;
    password: string;
    keyPath: string;
    keyPassphrase: string;
    sameSudo: boolean; // 管理者パスワードがログインのパスワードと同じ
    sudoPassword: string;
    name: string; // 呼び名（任意）
    webRoot: string;
    ownServer: boolean;
};

export const emptyForm: Form = {
    host: '',
    port: '22',
    user: '',
    authType: 'password',
    password: '',
    keyPath: '',
    keyPassphrase: '',
    sameSudo: true,
    sudoPassword: '',
    name: '',
    webRoot: '',
    ownServer: false,
};

// 実際に使う sudo パスワード
export const effectiveSudo = (f: Form) =>
    f.authType === 'password' && f.sameSudo ? f.password : f.sudoPassword;

const showSudoInput = (f: Form) => f.authType === 'key' || !f.sameSudo;

// 入力ミスをその場で知らせる
export function validate(f: Form): string[] {
    const errors: string[] = [];
    if (!f.host.trim()) errors.push('接続先を入力してください');
    const port = Number(f.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) errors.push('ポートは1〜65535の数字で入力してください');
    if (!f.user.trim()) errors.push('ユーザー名を入力してください');
    if (f.authType === 'password' && !f.password) errors.push('パスワードを入力してください');
    if (f.authType === 'key' && !f.keyPath) errors.push('鍵ファイルを選んでください');
    if (showSudoInput(f) && !f.sudoPassword) errors.push('管理者パスワード（sudo）を入力してください');
    if (!f.ownServer) errors.push('自分が管理しているサーバーか確認してください');
    return errors;
}

function today(): string {
    const d = new Date();
    return `${d.getFullYear()}.${String(d.getMonth() + 1).padStart(2, '0')}.${String(d.getDate()).padStart(2, '0')}`;
}

function fileName(path: string): string {
    return path.split(/[\\/]/).pop() ?? path;
}

type Props = {
    form: Form;
    onChange: (form: Form) => void;
    onSubmit: () => void;
};

export function Reception({form, onChange, onSubmit}: Props) {
    const errors = validate(form);
    const ready = errors.length === 0;

    const set = <K extends keyof Form>(key: K, value: Form[K]) => onChange({...form, [key]: value});

    function submit(e: FormEvent) {
        e.preventDefault();
        if (ready) onSubmit();
    }

    async function chooseKeyFile() {
        const path = await SelectKeyFile();
        if (path) set('keyPath', path);
    }

    const port = Number(form.port);
    const preview = 'ssh ' + (port && port !== 22 ? `-p ${port} ` : '') +
        (form.user.trim() || 'ユーザー名') + '@' + (form.host.trim() || 'IPアドレス');

    const sudoNote = form.authType === 'key'
        ? '鍵でログインする場合も、検査の一部に必要です。保存はしません。'
        : form.sameSudo ? 'ファイアウォールやSSH設定の検査に使います。' : '検査の一部に必要です。保存はしません。';

    return (
        <div className="desk">
            <header className="masthead">
                <div className="masthead-title">
                    <h1>サーバーカルテ</h1>
                    <span>自宅サーバーの健康診断・受付</span>
                </div>
                <span className="stamp">外部送信なし</span>
            </header>

            <div className="columns">
                <form className="paper reception" onSubmit={submit} noValidate>
                    <div className="paper-head">
                        <h2>受付票</h2>
                        <dl className="meta">
                            <div><dt>受付日</dt><dd>{today()}</dd></div>
                        </dl>
                    </div>

                    <div className="fields">
                        <div className="field">
                            <label htmlFor="r-host">接続先 <span className="req">※</span></label>
                            <div className="field-body">
                                <div className="host-port">
                                    <input id="r-host" className="line-input mono" value={form.host}
                                           onChange={e => set('host', e.target.value)}
                                           placeholder="192.168.56.104" autoComplete="off"/>
                                    <label className="port">
                                        <span>ポート</span>
                                        <input className="line-input mono" value={form.port} inputMode="numeric"
                                               onChange={e => set('port', e.target.value)}/>
                                    </label>
                                </div>
                                <span className="help">サーバーで <code>ip a</code> を実行すると確認できます</span>
                            </div>
                        </div>

                        <div className="field">
                            <label htmlFor="r-user">ユーザー名 <span className="req">※</span></label>
                            <div className="field-body">
                                <input id="r-user" className="line-input mono" value={form.user}
                                       onChange={e => set('user', e.target.value)}
                                       placeholder="user" autoComplete="off"/>
                                <span className="help">サーバーにログインするときの名前です</span>
                            </div>
                        </div>

                        <fieldset className="field">
                            <legend>認証方法</legend>
                            <div className="field-body">
                                <div className="choices">
                                    <label><input type="radio" name="r-auth" checked={form.authType === 'password'}
                                                  onChange={() => set('authType', 'password')}/>パスワード</label>
                                    <label><input type="radio" name="r-auth" checked={form.authType === 'key'}
                                                  onChange={() => set('authType', 'key')}/>鍵ファイル</label>
                                </div>
                                {form.authType === 'password' ? (
                                    <>
                                        <input type="password" className="line-input" aria-label="パスワード"
                                               placeholder="パスワード" value={form.password}
                                               onChange={e => set('password', e.target.value)} autoComplete="off"/>
                                        <span className="help">パスワードは保存しません。受付のたびに入力してください。</span>
                                    </>
                                ) : (
                                    <>
                                        <div className="key-file">
                                            <button type="button" className="outline" onClick={chooseKeyFile}>鍵ファイルを選ぶ</button>
                                            <span className="mono muted">{form.keyPath ? fileName(form.keyPath) : '未選択'}</span>
                                        </div>
                                        <input type="password" className="line-input" aria-label="鍵のパスフレーズ"
                                               placeholder="パスフレーズ（設定している場合）" value={form.keyPassphrase}
                                               onChange={e => set('keyPassphrase', e.target.value)} autoComplete="off"/>
                                    </>
                                )}
                            </div>
                        </fieldset>

                        <div className="field">
                            <label htmlFor="r-sudo">管理者パスワード<br/><span className="sub">（sudo）</span></label>
                            <div className="field-body">
                                {form.authType === 'password' && (
                                    <label className="inline-check">
                                        <input type="checkbox" checked={form.sameSudo}
                                               onChange={e => set('sameSudo', e.target.checked)}/>
                                        ログインのパスワードと同じ
                                    </label>
                                )}
                                {showSudoInput(form) && (
                                    <input id="r-sudo" type="password" className="line-input"
                                           placeholder="sudo のパスワード" value={form.sudoPassword}
                                           onChange={e => set('sudoPassword', e.target.value)} autoComplete="off"/>
                                )}
                                <span className="help">{sudoNote}</span>
                            </div>
                        </div>

                        <div className="field">
                            <label htmlFor="r-name">呼び名<span className="sub">（任意）</span></label>
                            <input id="r-name" className="line-input" value={form.name}
                                   onChange={e => set('name', e.target.value)} placeholder="おうちサーバー"/>
                        </div>

                        <div className="field">
                            <label htmlFor="r-webroot">公開フォルダ<span className="sub">（任意）</span></label>
                            <div className="field-body">
                                <input id="r-webroot" className="line-input mono" value={form.webRoot}
                                       onChange={e => set('webRoot', e.target.value)} placeholder="/var/www"
                                       autoComplete="off"/>
                                <span className="help">不要ファイル診断で調べる場所です。空欄なら /var/www を調べます</span>
                            </div>
                        </div>

                        <div className="field last">
                            <span className="field-label">検査内容</span>
                            <span className="field-text">待ち受けポート・SSH設定・不要ファイル・更新状況</span>
                        </div>
                    </div>

                    <div className="preview">
                        <span>この内容で、次のように接続します</span>
                        <code>{preview}</code>
                    </div>

                    <label className="inline-check own">
                        <input type="checkbox" checked={form.ownServer}
                               onChange={e => set('ownServer', e.target.checked)}/>
                        自分が管理しているサーバーです
                    </label>

                    <div className="actions">
                        <button type="submit" className="submit" aria-disabled={!ready} disabled={!ready}>
                            受付して診断する
                        </button>
                        <span className="muted small">
                            {ready ? '受付すると、すぐに診断が始まります' : (errors[0] ?? '')}
                        </span>
                    </div>
                </form>

                <aside className="side">
                    <section className="side-block">
                        <div className="side-head">
                            <h2>再診の方</h2>
                            <span className="muted small">選ぶと受付票に書き写します</span>
                        </div>
                        <div className="paper empty">
                            受診の記録はまだありません。<br/>
                            <span className="muted small">記録の保存は準備中です。</span>
                        </div>
                    </section>

                    <section className="paper help-box">
                        <h2>お困りの方へ</h2>
                        <ul>
                            <li>SSHで接続できない（導入手順）<span className="soon">準備中</span></li>
                            <li>IPアドレスの調べ方<span className="soon">準備中</span></li>
                            <li>検査で何を調べるの？<span className="soon">準備中</span></li>
                        </ul>
                    </section>

                    <p className="muted small">接続情報と診断結果は、このPCの外には送りません。</p>
                </aside>
            </div>
        </div>
    );
}
