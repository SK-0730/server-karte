// S02 ホスト鍵の確認（docs/SCREENS.md）
import {useState} from 'react';

type UnknownProps = {
    kind: 'unknown';
    fingerprint: string;
    onCancel: () => void;
    onConnect: () => void;
};

type MismatchProps = {
    kind: 'mismatch';
    fingerprint: string;
    expected: string;
    onClose: () => void;
};

export function HostKeyDialog(props: UnknownProps | MismatchProps) {
    const [open, setOpen] = useState(false);

    if (props.kind === 'mismatch') {
        return (
            <div className="overlay">
                <div className="dialog danger" role="alertdialog">
                    <h2>サーバーがすり替わっている可能性があります</h2>
                    <p>このサーバーの指紋が、前回記録したものと違います。安全のため接続を中止しました。</p>
                    <p className="label">記録した指紋</p>
                    <p className="codebox">{props.expected}</p>
                    <p className="label">今回の指紋</p>
                    <p className="codebox">{props.fingerprint}</p>
                    <p className="small muted">
                        サーバーを作り直した場合などにも指紋は変わります。心当たりがない場合は、接続しないでください。
                    </p>
                    <div className="dialog-buttons">
                        <button type="button" className="primary" onClick={props.onClose}>閉じる</button>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="overlay">
            <div className="dialog" role="dialog">
                <h2>はじめて接続するサーバーです</h2>
                <p className="label">このサーバーの指紋：</p>
                <p className="codebox">{props.fingerprint}</p>
                <button type="button" className="toggle" onClick={() => setOpen(v => !v)}>
                    {open ? '▲' : '▼'} なぜ確認するの？ / 確かめ方
                </button>
                {open && (
                    <div className="howto">
                        <p>
                            指紋は、サーバーの身分証明書の番号のようなものです。
                            途中で偽のサーバーにすり替えられていると、指紋が変わります。
                        </p>
                        <p>サーバーで次を実行し、同じか見比べます</p>
                        <p className="codebox">ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</p>
                        <p>一度確認すれば、次からは自動で照らし合わせます。</p>
                    </div>
                )}
                <div className="dialog-buttons">
                    <button type="button" onClick={props.onCancel}>やめる</button>
                    <button type="button" className="primary" onClick={props.onConnect}>接続する</button>
                </div>
            </div>
        </div>
    );
}
