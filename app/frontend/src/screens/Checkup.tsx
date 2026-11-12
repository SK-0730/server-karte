// S03 診察中（docs/SCREENS.md）
export type StepStatus = 'waiting' | 'running' | 'done';

export type Step = {
    id: string;
    label: string;
    status: StepStatus;
    detail?: string;
    ready: boolean; // false の診断はまだ作っていない（WBS 4.1〜4.4）
};

export const initialSteps = (): Step[] => [
    {id: 'connect', label: '接続', status: 'waiting', ready: true},
    {id: 'os', label: 'OSの確認', status: 'waiting', ready: true},
    {id: 'ports', label: 'ポート診断', status: 'waiting', ready: false},
    {id: 'sshconfig', label: 'SSH設定診断', status: 'waiting', ready: false},
    {id: 'files', label: '不要ファイル診断', status: 'waiting', ready: false},
    {id: 'packages', label: 'パッケージ更新診断', status: 'waiting', ready: false},
];

type Props = {
    host: string;
    steps: Step[];
    finished: boolean;
    onCancel: () => void;
    onBack: () => void;
};

const mark = (s: Step) => {
    if (s.status === 'done') return <span className="mark done" aria-label="完了">✓</span>;
    if (s.status === 'running') return <span className="mark running" aria-label="実行中">◌</span>;
    return <span className="mark" aria-hidden="true">・</span>;
};

export function Checkup({host, steps, finished, onCancel, onBack}: Props) {
    return (
        <div className="desk checkup">
            <header className="masthead">
                <div className="masthead-title">
                    <h1>サーバーカルテ</h1>
                    <span>自宅サーバーの健康診断</span>
                </div>
                <span className="stamp">外部送信なし</span>
            </header>

            <section className="paper">
                <div className="paper-head">
                    <h2>{finished ? '診察結果' : '診察中'}</h2>
                    <span className="host">{host}</span>
                </div>
                <ul className="steps" aria-live="polite">
                    {steps.map(s => (
                        <li key={s.id} className={`step ${s.status}`}>
                            {mark(s)}
                            <span>{s.label}</span>
                            {s.detail && <span className="detail">（{s.detail}）</span>}
                            {s.status === 'running' && <span className="detail">…</span>}
                            {!s.ready && <span className="soon" style={{marginLeft: 'auto'}}>準備中</span>}
                        </li>
                    ))}
                </ul>
                <div className="actions">
                    {finished ? (
                        <>
                            <span className="muted small">接続とOSの確認ができました。各診断は準備中です。</span>
                            <button type="button" className="submit" onClick={onBack}>受付に戻る</button>
                        </>
                    ) : (
                        <button type="button" className="secondary" onClick={onCancel}>中止</button>
                    )}
                </div>
            </section>
        </div>
    );
}
