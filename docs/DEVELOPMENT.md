# 開発ガイド

## 構成

| ディレクトリ | 内容 |
| --- | --- |
| `site/` | Webサイト（nginx + 静的HTML）。Dockerイメージにして自宅サーバーへデプロイ |
| `app/` | デスクトップアプリ（Wails v2 / Go + React + TypeScript）。Windows向けexeをビルド |
| `.github/workflows/` | CI/CD定義 |

## 開発の流れ

1. 作業用ブランチを作る（`main` に直接pushしない）
2. 変更してコミット・push
3. Pull Requestを作る → CIでビルド確認
4. `main` にマージ → 自宅サーバーへ自動デプロイ

```
ブランチでpush ──▶ PR作成 ──▶ CI（ビルドのみ）
                                   │
                         mainへマージ
                                   ▼
               GHCRへイメージpush ──▶ Tailscale経由でprodへSSH
                                   ──▶ docker compose pull && up -d
```

## CI/CD

### `ci.yml`（site）

| きっかけ | 動き |
| --- | --- |
| PR | `site/` をDockerビルド（pushしない） |
| `main` へpush | `ghcr.io/<owner>/<repo>:latest` としてpush → `deploy` ジョブ実行 |

`deploy` ジョブ：
- Tailscaleに `tag:ci` で接続
- `dev@prod` にSSHし、`~/server-karte` で `docker compose pull && docker compose up -d`

必要なSecrets：`TS_OAUTH_CLIENT_ID` / `TS_OAUTH_SECRET`

### `app.yml`（app）

- `app/**` に変更がある PR / `main` へのpush で実行
- `windows-latest` で `wails build -platform windows/amd64`
- 成果物 `server-karte-windows`（exe）をArtifactとしてアップロード

## ローカルでの確認

### site

```bash
cd site
docker compose up --build
```

http://localhost:8080 で確認できます。

### app

```bash
go install github.com/wailsapp/wails/v2/cmd/wails@v2.17.0
cd app
wails dev
```

## 注意

- リポジトリ内の `site/compose.yaml` は `build: .`（ローカルビルド用）です。
  自宅サーバーの `~/server-karte` では、GHCRのイメージを使うcompose設定になっている前提です。
