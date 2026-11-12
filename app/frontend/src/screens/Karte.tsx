// S04 カルテ（結果一覧）と S05 所見の詳細（docs/SCREENS.md）
import {useState} from 'react';
import {karte, main} from '../../wailsjs/go/models';
import {mask, MaskTargets} from '../mask';

// まだ作っていない診断（WBS 4.2〜4.4）も、一覧には「準備中」として並べる
const ALL_CHECKS = [
    {id: 'ports', name: 'ポート診断'},
    {id: 'sshconfig', name: 'SSH設定診断'},
    {id: 'files', name: '不要ファイル診断'},
    {id: 'packages', name: 'パッケージ更新診断'},
];

const GRADE_LABEL: Record<string, string> = {A: '問題なし', B: '軽微', C: '要注意', D: '危険', E: '緊急'};
const GRADE_MESSAGE: Record<string, string> = {
    A: '大きな問題は見つかりませんでした',
    B: '気になる点が少しあります',
    C: '直したほうがよい点があります',
    D: '早めに直しましょう',
    E: '今すぐ直しましょう',
};

export function GradeBadge({grade, big = false}: { grade: string; big?: boolean }) {
    return (
        <span className={`grade grade-${grade}${big ? ' big' : ''}`} aria-label={`判定 ${grade}（${GRADE_LABEL[grade]}）`}>
            {grade}
        </span>
    );
}

type Props = {
    title: string; // 呼び名（接続先）
    result: main.ConnectionResult;
    maskTargets: MaskTargets;
    onRetry: () => void;
    onNew: () => void;
};

export function Karte({title, result, maskTargets, onRetry, onNew}: Props) {
    const [openCheck, setOpenCheck] = useState<string | null>(null);
    const checks = result.checks ?? [];
    const opened = checks.find(c => c.checkId === openCheck);

    if (opened) {
        return <CheckDetail title={title} check={opened} maskTargets={maskTargets} onBack={() => setOpenCheck(null)}/>;
    }

    const grade = result.overallGrade || 'A';
    const done = new Map(checks.map(c => [c.checkId, c]));
    // 診断済みを判定の悪い順に、そのあとに準備中を並べる（SCREENS.md S04）
    const rows = [
        ...checks,
        ...ALL_CHECKS.filter(c => !done.has(c.id)).map(c => ({checkId: c.id, name: c.name, pending: true})),
    ];

    return (
        <div className="desk">
            <Masthead/>
            <section className="paper">
                <div className="paper-head">
                    <h2>カルテ</h2>
                    <dl className="meta">
                        <div><dt>受診者</dt><dd>{title}</dd></div>
                        <div><dt>診断日</dt><dd>{result.finishedAt}</dd></div>
                    </dl>
                </div>

                <div className="overall">
                    <span className="overall-label">総合判定</span>
                    <GradeBadge grade={grade} big/>
                    <div>
                        <p className="overall-message">{GRADE_MESSAGE[grade]}</p>
                        <p className="muted small">{result.os?.prettyName}・いちばん悪い項目の判定に合わせています</p>
                    </div>
                </div>

                <ul className="check-list">
                    {rows.map(r => 'pending' in r ? (
                        <li key={r.checkId} className="check-row pending">
                            <span className="check-name">{r.name}</span>
                            <span className="soon">準備中</span>
                        </li>
                    ) : (
                        <li key={r.checkId}>
                            <button type="button" className="check-row" onClick={() => setOpenCheck(r.checkId)}>
                                <span className="check-name">{r.name}</span>
                                <GradeBadge grade={r.grade}/>
                                <span className="check-summary">{r.summary}</span>
                                <span className="chevron" aria-hidden="true">›</span>
                            </button>
                        </li>
                    ))}
                </ul>

                <div className="actions">
                    <button type="button" className="submit" onClick={onRetry}>もう一度診断</button>
                    <button type="button" className="secondary" onClick={onNew}>新しく受付</button>
                    <span className="muted small">直したあとに「もう一度診断」で、直ったか確かめられます</span>
                </div>
            </section>
        </div>
    );
}

export function Masthead() {
    return (
        <header className="masthead">
            <div className="masthead-title">
                <h1>サーバーカルテ</h1>
                <span>自宅サーバーの健康診断</span>
            </div>
            <span className="stamp">外部送信なし</span>
        </header>
    );
}

// S05 所見の詳細
function CheckDetail({title, check, maskTargets, onBack}: {
    title: string;
    check: karte.CheckResult;
    maskTargets: MaskTargets;
    onBack: () => void;
}) {
    const findings = check.findings ?? [];
    const [open, setOpen] = useState<number | null>(findings.length > 0 ? 0 : null);
    const [showEvidence, setShowEvidence] = useState(false);

    return (
        <div className="desk">
            <Masthead/>
            <section className="paper">
                <div className="paper-head">
                    <button type="button" className="back" onClick={onBack}>‹ カルテに戻る</button>
                    <h2>{check.name}</h2>
                    <GradeBadge grade={check.grade}/>
                </div>
                <p className="detail-sub muted small">{title}・{check.summary}</p>

                <ol className="findings">
                    {findings.map((f, i) => (
                        <li key={i} className="finding">
                            <button type="button" className="finding-head" aria-expanded={open === i}
                                    onClick={() => setOpen(open === i ? null : i)}>
                                <GradeBadge grade={f.grade}/>
                                <span className="finding-title">{f.title}</span>
                                <span className="chevron" aria-hidden="true">{open === i ? '▲' : '▼'}</span>
                            </button>
                            {open === i && <FindingBody finding={f} check={check} maskTargets={maskTargets}/>}
                        </li>
                    ))}
                </ol>

                <div className="evidence">
                    <button type="button" className="toggle" aria-expanded={showEvidence}
                            onClick={() => setShowEvidence(v => !v)}>
                        {showEvidence ? '▲' : '▼'} 根拠（実行したコマンドと結果）
                    </button>
                    {showEvidence && <pre className="codebox">{check.evidence}</pre>}
                </div>
            </section>
        </div>
    );
}

function FindingBody({finding, check, maskTargets}: {
    finding: karte.Finding;
    check: karte.CheckResult;
    maskTargets: MaskTargets;
}) {
    const [copied, setCopied] = useState(false);

    async function copyPrompt() {
        const text = mask(buildPrompt(finding, check), maskTargets);
        try {
            await navigator.clipboard.writeText(text);
            setCopied(true);
            setTimeout(() => setCopied(false), 2500);
        } catch {
            setCopied(false);
        }
    }

    return (
        <div className="finding-body">
            <h3>何が起きている？</h3>
            <p>{finding.what}</p>
            <h3>なぜ危ない？</h3>
            <p>{finding.why}</p>
            <h3>どう直す？</h3>
            <p className="steps-text">{finding.howToFix}</p>
            {finding.grade !== 'A' && (
                <>
                    <h3>AIに相談する</h3>
                    <div className="ai-row">
                        <button type="button" className="outline" onClick={copyPrompt}>相談文をコピー</button>
                        <span className="muted small" role="status">
                            {copied ? 'コピーしました。IPアドレスなどは伏せてあります。' : 'IPアドレス・ユーザー名などは伏せてコピーします'}
                        </span>
                    </div>
                </>
            )}
        </div>
    );
}

function buildPrompt(f: karte.Finding, check: karte.CheckResult): string {
    return [
        '自宅サーバー（Ubuntu）をサーバーカルテで診断したところ、次の指摘がありました。',
        '初心者にも分かるように、直し方を順番に教えてください。設定を変える前に確認すべきことがあれば、それも教えてください。',
        '',
        `【診断】${check.name}（判定 ${f.grade}：${GRADE_LABEL[f.grade]}）`,
        `【指摘】${f.title}`,
        `【内容】${f.what}`,
        '',
        '【根拠（コマンドの実行結果）】',
        check.evidence,
    ].join('\n');
}
