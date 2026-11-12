// 外に出す文（AI相談文・レポート書き出し）から、IPアドレス・ホスト名・ユーザー名を伏せる。
// 画面の表示には使わない（SCREENS.md 4章：画面は伏せない）。

const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const IPV6 = /\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b/gi;

function escapeRegExp(s: string): string {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export type MaskTargets = {
    host: string; // 接続先（IPアドレスまたはホスト名）
    user: string; // ユーザー名
    name?: string; // 呼び名
};

// ただし 0.0.0.0 と 127.x は伏せない（「どこから届くか」の説明に必要で、個人を特定しないため）。
function keepIp(ip: string): boolean {
    return ip === '0.0.0.0' || ip.startsWith('127.');
}

export function mask(text: string, t: MaskTargets): string {
    let out = text;
    const words: [string, string][] = [];
    if (t.name?.trim()) words.push([t.name.trim(), '[呼び名]']);
    if (t.host.trim() && !/^[\d.]+$/.test(t.host.trim())) words.push([t.host.trim(), '[ホスト名]']);
    if (t.user.trim()) words.push([t.user.trim(), '[ユーザー]']);
    // 長いものから置き換える（短い語が長い語の一部を壊さないように）
    words.sort((a, b) => b[0].length - a[0].length);
    for (const [w, r] of words) {
        // ユーザー名は単語として現れるときだけ置き換える（例：/home/dev/、dev@）
        const re = new RegExp(`(?<![A-Za-z0-9_-])${escapeRegExp(w)}(?![A-Za-z0-9_-])`, 'g');
        out = out.replace(re, r);
    }
    out = out.replace(IPV4, ip => (keepIp(ip) ? ip : '[IP]'));
    out = out.replace(IPV6, ip => (ip === '::1' ? ip : '[IP]'));
    return out;
}
