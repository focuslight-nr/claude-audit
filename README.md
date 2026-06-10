# CLAUDE-AUDIT

[日本語版 README はこちら / Japanese README](README_ja.md)

A read-only CLI tool for macOS that audits local Claude Code / Claude Desktop
configuration. It inspects MCP servers, hooks, permission settings, trusted
projects, sensitive file permissions, and data retention, reporting findings
at three severity levels: `WARN` / `REVIEW` / `INFO`.

> **Unofficial project.** Not affiliated with, endorsed by, sponsored by, or maintained by Anthropic.

Sister tool: [codex-audit](../codex-audit) (for OpenAI Codex). Both share a
common output schema and can be browsed and compared over time with
[audit-viewer](../audit-viewer).

## Features

- **Read-only** — never modifies or deletes any configuration
- **Minimal dependencies** — zsh + standard macOS commands (`jq` recommended for deep JSON parsing)
- **Automatic secret redaction** — values matching token / api_key / password patterns become `[REDACTED]`
- **CI friendly** — `--fail-on warn|review` signals findings via exit codes

## What it audits

| Section | Contents |
|---|---|
| Config | `~/.claude.json` (model settings, permissions) |
| Projects | Trusted projects (`hasTrustDialogAccepted`), pre-approved tools, per-project MCP |
| MCP Servers | MCP servers from `settings.json` / `.mcp.json` / `claude_desktop_config.json`; WARN on command-capable runtimes (bash/python/node, etc.) |
| Hooks | Hooks from all settings sources, with risk tags (network / destructive / git-write / sudo, etc.) |
| Permissions | `bypassPermissionsGate` activation, allow/deny lists in settings |
| Desktop | Cowork scheduled tasks, web search, HIPAA restriction settings |
| Sensitive Files | Permission checks on auth files, `config.json`, `buddy-tokens.json`, etc. |
| Retention | Size/count of sessions, shell-snapshots, projects, Cowork files |
| Runtime | Active sessions, related processes, LaunchAgents, crontab entries |

## Usage

```sh
./claude_audit.sh                  # terminal report
./claude_audit.sh --summary        # one-line summary + top findings
./claude_audit.sh --json           # JSON output (for audit-viewer etc.)
./claude_audit.sh --html           # HTML report (claude_audit_<timestamp>.html)
./claude_audit.sh --html report.html
./claude_audit.sh --json --output snapshot.json
./claude_audit.sh --fail-on warn   # exit 2 if any WARN (for CI)
./claude_audit.sh --redact-paths   # mask username/home paths in output
./claude_audit.sh --all-users      # audit every user on the machine (needs privileges)
./claude_audit.sh --claude-dir /path/to/.claude
```

### Options

| Option | Description |
|---|---|
| `--json` | JSON output |
| `--html [FILE]` | Generate an HTML report (auto-named if FILE omitted) |
| `--summary` | Summary only |
| `--output FILE` | Write output to FILE |
| `--fail-on warn\|review` | Non-zero exit if matching severity found (warn=2, review=1) |
| `--redact-paths` | Mask username and home directory |
| `--user USER` / `--all-users` | Target a specific user / all users |
| `--claude-dir DIR` | Explicit `.claude` directory location |
| `-q, --quiet` | Hide INFO findings |

## Severity levels

| Level | Meaning |
|---|---|
| `WARN` | High security impact; review and remediation recommended (trusted projects, permission-gate bypass, command-capable MCP servers, loose file permissions, etc.) |
| `REVIEW` | Not an immediate problem, but verify it is intentional (presence of MCP servers, hooks, pre-approved tools, etc.) |
| `INFO` | Inventory information (versions, counts, sizes, etc.) |

## JSON schema (common format)

The top-level structure is identical to codex-audit, so audit results from
multiple vendors can flow through the same pipeline.

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

## Requirements

- macOS (exits on anything other than Darwin)
- zsh (macOS default)
- `jq` (recommended; without it, deep parsing of JSON settings is skipped) — `brew install jq`

## Exit codes

| Code | Condition |
|---|---|
| 0 | Success |
| 1 | REVIEW found with `--fail-on review` / argument error |
| 2 | WARN found with `--fail-on warn` |

## License

MIT
