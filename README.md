# CLAUDE-AUDIT

[日本語版 README はこちら / Japanese README](README_ja.md)

A read-only CLI tool for macOS and Windows that audits local Claude Code / Claude Desktop
configuration. It inspects MCP servers, hooks, permission settings, trusted
projects, sensitive file permissions, and data retention, reporting findings
at three severity levels: `WARN` / `REVIEW` / `INFO`.

> **Unofficial project.** Not affiliated with, endorsed by, sponsored by, or maintained by Anthropic.

Sister tool: [codex-audit](../codex-audit) (for OpenAI Codex). Both share a
common output schema and can be browsed and compared over time with
[audit-viewer](../audit-viewer).

## Features

- **Read-only** — never modifies or deletes any configuration
- **Minimal dependencies** — zsh + standard macOS commands (`jq` recommended for deep JSON parsing), or Windows PowerShell 5.1+ / PowerShell 7+ with no extra modules
- **Automatic secret redaction** — values matching token / api_key / password patterns become `[REDACTED]`
- **CI friendly** — `--fail-on warn|review` signals findings via exit codes

## What it audits

Tracks the Claude Code **2.1.x** configuration surface.

| Section | Contents |
|---|---|
| Config | `~/.claude.json` — model, account/organization, machine ID, plugin & skill usage history |
| Managed Policy | Enterprise settings — macOS: `/Library/Application Support/ClaudeCode/managed-settings.json`, the `managed-settings.d/` drop-in directory, and MDM managed preferences; Windows: `%ProgramFiles%\ClaudeCode\managed-settings.json`, `managed-settings.d\`, and the `HKLM`/`HKCU` `SOFTWARE\Policies\ClaudeCode` registry keys |
| Projects | Trusted projects (`hasTrustDialogAccepted`), pre-approved tools, project-local MCP servers, CLAUDE.md external-include approval |
| MCP Servers | Servers from `settings.json`, `.mcp.json`, per-project `.claude.json` entries, plugin `.mcp.json`, and `claude_desktop_config.json`; WARN on command-capable runtimes (bash/python/node, etc.) |
| Hooks | All hook types — `command`, `http`, `mcp_tool`, `prompt`, `agent` — from every settings scope and plugin `hooks.json`, with risk tags (network, destructive, sudo, dynamic-code-execution, remote-endpoint, credential-header, async-background). Flags HTTP hooks with no `allowedHttpHookUrls` allowlist and unrecognized event names |
| Plugins | Installed marketplace plugins, skills-directory plugins, and enabled-plugin declarations; provenance (Anthropic-published vs third-party) and the executable surface each one ships (`hooks`, `mcp`, `lsp`, `monitors`, `bin`, `agents`, `skills`) |
| Monitors | Background monitor commands that plugins run unsandboxed for the whole session |
| Skills / Agents | User, project, and plugin `SKILL.md` / agent / command definitions, including declared tool access |
| Security Settings | Credential helpers (`apiKeyHelper`, `awsCredentialExport`, `awsAuthRefresh`), injected `env` keys, `sandbox.filesystem` / `sandbox.network` isolation, `permissions.defaultMode` / `additionalDirectories`, `statusLine`, marketplace controls, MCP allow/deny policy, `crossSessionInbound`, auto-mode rules, `cleanupPeriodDays`, and managed-only hardening switches |
| Desktop | Cowork scheduled tasks, web search, HIPAA restriction, permission-gate bypass |
| Sensitive Files | Permission checks (file mode on macOS, ACL on Windows) on `~/.claude.json`, settings files, session peer-token keys (`sessions/*.key`), `.credentials.json` / login keychain, `config.json`, `buddy-tokens.json`, `ant-did` |
| Retention | Size/count of sessions, shell-snapshots, projects, tasks, telemetry spool, plugin cache/data, Cowork files |
| Runtime | Installed version, active sessions, background task records, related processes; LaunchAgents and crontab entries on macOS, scheduled tasks and `Run` registry autostart entries on Windows |

Secrets are never read: only key names, file modes, and command strings are reported, and values matching token/password patterns are replaced with `[REDACTED]`.

> **Platform parity:** `claude_audit.sh` and `claude_audit.ps1` (both v0.2.0) implement
> the same check set and emit the same JSON schema. Platform-specific details differ where
> the operating systems do: file modes vs. Windows ACLs, LaunchAgents/crontab vs. scheduled
> tasks and `Run` registry keys, and the managed-policy delivery paths listed below.

## Usage

### Windows (PowerShell)

```powershell
.\claude_audit.ps1
.\claude_audit.ps1 --summary
.\claude_audit.ps1 --json
.\claude_audit.ps1 --html
.\claude_audit.ps1 --json --output snapshot.json
.\claude_audit.ps1 --fail-on warn
```

If the execution policy blocks the script:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\claude_audit.ps1 --summary
```

### macOS

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
  "plugins": [], "skills": [], "monitors": [], "security_settings": [],
  "active_sessions": [], "sensitive_files": [], "retention": []
}
```

## Requirements

- Windows 10/11 with Windows PowerShell 5.1+ or PowerShell 7+
- macOS with zsh (macOS default)
- `jq` is recommended for the macOS version only

## Exit codes

| Code | Condition |
|---|---|
| 0 | Success |
| 1 | REVIEW found with `--fail-on review` / argument error |
| 2 | WARN found with `--fail-on warn` |

## License

MIT
