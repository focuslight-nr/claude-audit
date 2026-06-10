# CLAUDE-AUDIT

[English README](README.md)

Claude Code / Claude Desktop のローカル設定を読み取り専用で監査する macOS 用 CLI ツールです。
MCP サーバ・hooks・権限設定・信頼済みプロジェクト・機密ファイルのパーミッション・データ保持状況などを点検し、`WARN` / `REVIEW` / `INFO` の3段階で報告します。

> **Unofficial project.** Not affiliated with, endorsed by, sponsored by, or maintained by Anthropic.

姉妹ツール: [codex-audit](../codex-audit)（OpenAI Codex 用）。両者は共通の出力スキーマを持ち、[audit-viewer](../audit-viewer) で統合的に閲覧・日時比較できます。

## 特徴

- **読み取り専用** — 設定の変更・削除は一切行いません
- **依存最小** — zsh + macOS 標準コマンドのみで動作（JSON の深掘り解析には `jq` を推奨）
- **シークレットの自動マスク** — token / api_key / password 等にマッチする値は `[REDACTED]` 化
- **CI 連携** — `--fail-on warn|review` で終了コードによる検知が可能

## 監査対象

| セクション | 内容 |
|---|---|
| Config | `~/.claude.json`（モデル設定・パーミッション） |
| Projects | 信頼済みプロジェクト（`hasTrustDialogAccepted`）・事前許可ツール・プロジェクト別 MCP |
| MCP Servers | `settings.json` / `.mcp.json` / `claude_desktop_config.json` の MCP サーバ。コマンド実行可能なランタイム（bash/python/node 等）を WARN 検出 |
| Hooks | 全設定ソースのフック。network / destructive / git-write / sudo 等のリスクタグ付け |
| Permissions | `bypassPermissionsGate` の有効化、settings の allow/deny リスト |
| Desktop | Cowork スケジュールタスク・Web 検索・HIPAA 制限の設定 |
| Sensitive Files | `auth` 系・`config.json`・`buddy-tokens.json` 等のパーミッション点検 |
| Retention | sessions / shell-snapshots / projects / Cowork ファイルのサイズ・件数 |
| Runtime | アクティブセッション・関連プロセス・LaunchAgent・crontab エントリ |

## 使い方

```sh
./claude_audit.sh                  # ターミナルレポート
./claude_audit.sh --summary        # 1行サマリ + 上位 findings
./claude_audit.sh --json           # JSON 出力（audit-viewer 等での取り込み用）
./claude_audit.sh --html           # HTML レポート（claude_audit_<日時>.html）
./claude_audit.sh --html report.html
./claude_audit.sh --json --output snapshot.json
./claude_audit.sh --fail-on warn   # WARN があれば exit 2（CI 向け）
./claude_audit.sh --redact-paths   # 出力からユーザー名/ホームパスをマスク
./claude_audit.sh --all-users      # マシン上の全ユーザーを監査（要権限）
./claude_audit.sh --claude-dir /path/to/.claude
```

### オプション

| オプション | 説明 |
|---|---|
| `--json` | JSON 形式で出力 |
| `--html [FILE]` | HTML レポートを生成（FILE 省略時は自動命名） |
| `--summary` | サマリのみ表示 |
| `--output FILE` | 出力先ファイルを指定 |
| `--fail-on warn\|review` | 該当 severity があれば非ゼロ終了（warn=2, review=1） |
| `--redact-paths` | ユーザー名・ホームディレクトリをマスク |
| `--user USER` / `--all-users` | 対象ユーザーの指定 / 全ユーザー監査 |
| `--claude-dir DIR` | `.claude` ディレクトリの場所を明示指定 |
| `-q, --quiet` | INFO findings を非表示 |

## 重大度

| レベル | 意味 |
|---|---|
| `WARN` | セキュリティ上の影響が大きく、確認・是正を推奨（信頼済みプロジェクト、権限ゲートのバイパス、コマンド実行可能な MCP、緩いファイルパーミッション等） |
| `REVIEW` | 即時の問題ではないが意図したものか確認すべき項目（MCP サーバの存在、hooks、事前許可ツール等） |
| `INFO` | インベントリ情報（バージョン、件数、サイズ等） |

## JSON スキーマ（共通形式）

codex-audit と同一のトップレベル構造を採用しており、複数ベンダーの監査結果を同じパイプラインで処理できます。

```json
{
  "timestamp": "2026-06-10T14:52:10Z",
  "hostname": "...",
  "username": "...",
  "claude_dir": "/Users/you/.claude",
  "summary": { "warn": 2, "review": 2, "info": 15 },
  "findings": [
    { "severity": "WARN", "section": "Projects", "message": "...", "detail": "..." }
  ],
  "mcp_servers": [], "projects": [], "hooks": [],
  "active_sessions": [], "sensitive_files": [], "retention": []
}
```

## 動作要件

- macOS（Darwin 以外では起動時に終了します）
- zsh（macOS 標準）
- `jq`（推奨。未導入の場合 JSON 設定の深掘り解析がスキップされます）— `brew install jq`

## 終了コード

| コード | 条件 |
|---|---|
| 0 | 正常終了 |
| 1 | `--fail-on review` で REVIEW あり / 引数エラー |
| 2 | `--fail-on warn` で WARN あり |

## License

MIT
