#!/bin/zsh
# CLAUDE-AUDIT - Claude Code local security audit tool (macOS/Zsh)
# Read-only audit for ~/.claude configuration, MCP servers, hooks, sessions, and projects.
# Unofficial project. Not affiliated with, endorsed by, sponsored by, or maintained by Anthropic.
setopt PIPE_FAIL KSH_ARRAYS BASH_REMATCH TYPESET_SILENT NULL_GLOB

VERSION="0.1.0"
SCRIPT_NAME="${0:t}"
CLAUDE_DIR_NAME=".claude"
DANGEROUS_MCP_HINTS="bash sh zsh python python3 node ruby perl osascript sqlite3 psql mysql curl wget nc ncat ssh scp"
SENSITIVE_NAME_RE='(token|secret|password|passwd|api[_-]?key|credential|auth|session|cookie)'
HAS_JQ=false

AUDIT_USER=""
HOME_DIR=""
CLAUDE_DIR=""
TIMESTAMP=""
HOSTNAME_VAL=""
OPT_JSON=false
OPT_QUIET=false
OPT_HTML=""
OPT_ALL_USERS=false
OPT_REDACT_PATHS=false
OPT_DIFF=""
OPT_DIFF_JSON=false
OPT_FAIL_ON=""
OPT_OUTPUT=""
OPT_SUMMARY=false
OPT_CLAUDE_DIR=""

FINDING_SEV=()
FINDING_SECT=()
FINDING_MSG=()
FINDING_DET=()

MCP_NAMES=()
declare -A MCP_CMDS MCP_ARGS MCP_ENVKEYS MCP_TYPE

PROJECTS=()
HOOKS=()
ALLOWED_TOOLS=()
SENSITIVE_FILES=()
RETENTION_ITEMS=()
FEATURE_FLAGS=()
ACTIVE_SESSIONS=()

WARN_COUNT=0
INFO_COUNT=0
REVIEW_COUNT=0

preflight() {
    if [[ "$(uname -s 2>/dev/null)" != "Darwin" ]]; then
        print -r -- "CLAUDE-AUDIT currently supports macOS only. Detected: $(uname -s 2>/dev/null || echo unknown)" >&2
        exit 1
    fi
    command -v jq >/dev/null 2>&1 && HAS_JQ=true || HAS_JQ=false
}

add_finding() {
    local sev="$1" sect="$2" msg="$3" det="${4:-}"
    FINDING_SEV+=("$sev")
    FINDING_SECT+=("$sect")
    FINDING_MSG+=("$msg")
    FINDING_DET+=("$det")
    case "$sev" in
        WARN) ((WARN_COUNT++)) ;;
        REVIEW) ((REVIEW_COUNT++)) ;;
        *) ((INFO_COUNT++)) ;;
    esac
}

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\r'/\\r}"
    printf '%s' "$s"
}

jstr() {
    printf '"%s"' "$(json_escape "$1")"
}

display_text() {
    local s="$1"
    if [[ "$OPT_REDACT_PATHS" == "true" ]]; then
        [[ -n "$HOME_DIR" ]] && s="${s//${HOME_DIR}/~}"
        [[ -n "$AUDIT_USER" ]] && s="${s//\/Users\/${AUDIT_USER}/\/Users\/[USER]}"
    fi
    printf '%s' "$s"
}

jstr_out() {
    jstr "$(display_text "$1")"
}

html_escape() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    s="${s//\'/&#39;}"
    printf '%s' "$s"
}

html_out() {
    html_escape "$(display_text "$1")"
}

strip_quotes() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    s="${s#\"}"
    s="${s%\"}"
    printf '%s' "$s"
}

redact_value() {
    local key="$1" val="$2"
    if [[ "${(L)key}" =~ "$SENSITIVE_NAME_RE" || "${(L)val}" =~ '(sk-ant-|bearer |token=|secret=|password=|api[_-]?key=)' ]]; then
        printf '[REDACTED]'
    else
        printf '%s' "$val"
    fi
}

mcp_env_risk_tags() {
    local keys="$1" tags=() lower
    lower="${(L)keys}"
    [[ "$lower" =~ '(token|secret|password|passwd|api[_-]?key|credential|auth|cookie)' ]] && tags+=("secret-like-env")
    [[ "$lower" == *"trusted"* || "$lower" == *"allowlist"* ]] && tags+=("trust-or-allowlist")
    [[ "$lower" == *"path"* || "$lower" == *"dirs"* || "$lower" == *"home"* ]] && tags+=("filesystem-scope")
    [[ "$lower" == *"browser"* || "$lower" == *"backend"* ]] && tags+=("browser-scope")
    local IFS=","
    printf '%s' "${tags[*]}"
}

hook_risk_tags() {
    local cmd="$1" tags=() lower
    lower="${(L)cmd}"
    [[ "$lower" == *"curl"* || "$lower" == *"wget"* || "$lower" == *"http"* ]] && tags+=("network")
    [[ "$lower" == *"rm "* || "$lower" == *"delete"* ]] && tags+=("destructive")
    [[ "$lower" == *"git push"* || "$lower" == *"git commit"* ]] && tags+=("git-write")
    [[ "$lower" == *"osascript"* || "$lower" == *"open -a"* ]] && tags+=("gui-or-applescript")
    [[ "$lower" == *"sudo"* ]] && tags+=("elevated-privilege")
    local IFS=","
    printf '%s' "${tags[*]}"
}

fmt_bytes() {
    local n="$1"
    if ((n < 1024)); then printf '%d B' "$n"
    elif ((n < 1048576)); then printf '%.1f KB' "$((n / 1024.0))"
    elif ((n < 1073741824)); then printf '%.1f MB' "$((n / 1048576.0))"
    else printf '%.1f GB' "$((n / 1073741824.0))"; fi
}

file_mode() {
    local p="$1"
    stat -f '%Lp' "$p" 2>/dev/null || printf ''
}

dir_file_count() {
    local d="$1"
    [[ -d "$d" ]] || { printf '0'; return 0; }
    find "$d" -type f 2>/dev/null | wc -l | tr -d ' '
}

dir_total_bytes() {
    local d="$1"
    [[ -d "$d" ]] || { printf '0'; return 0; }
    find "$d" -type f -print0 2>/dev/null | xargs -0 stat -f '%z' 2>/dev/null | awk '{s+=$1} END {print s+0}'
}

dir_latest_mtime() {
    local d="$1"
    [[ -d "$d" ]] || { printf ''; return 0; }
    find "$d" -type f -print0 2>/dev/null | xargs -0 stat -f '%m' 2>/dev/null | sort -nr | head -1 | while read -r ts; do
        [[ -n "$ts" ]] && date -r "$ts" '+%Y-%m-%dT%H:%M:%S%z'
    done
}

get_user_home() {
    local user="$1"
    if [[ -z "$user" || "$user" == "$(id -un)" ]]; then
        printf '%s' "$HOME"
        return 0
    fi
    if command -v dscl >/dev/null 2>&1; then
        dscl . -read "/Users/$user" NFSHomeDirectory 2>/dev/null | awk '{print $2}'
    fi
}

discover_claude_users() {
    local user home
    if ! command -v dscl >/dev/null 2>&1; then
        return 0
    fi
    dscl . -list /Users 2>/dev/null | while IFS= read -r user; do
        [[ "$user" == _* || "$user" == "." || "$user" == "daemon" || "$user" == "nobody" || "$user" == "root" ]] && continue
        home=$(get_user_home "$user")
        [[ -f "$home/.claude.json" ]] && print -r -- "$user"
    done
}

reset_state() {
    FINDING_SEV=()
    FINDING_SECT=()
    FINDING_MSG=()
    FINDING_DET=()
    MCP_NAMES=()
    MCP_CMDS=()
    MCP_ARGS=()
    MCP_ENVKEYS=()
    MCP_TYPE=()
    PROJECTS=()
    HOOKS=()
    ALLOWED_TOOLS=()
    SENSITIVE_FILES=()
    RETENTION_ITEMS=()
    FEATURE_FLAGS=()
    ACTIVE_SESSIONS=()
    WARN_COUNT=0
    INFO_COUNT=0
    REVIEW_COUNT=0
}

# Parse MCP server entries from a JSON object using jq or simple grep
parse_mcp_servers_from_json() {
    local file="$1" source_label="$2"
    [[ -r "$file" ]] || return 0

    if [[ "$HAS_JQ" == "true" ]]; then
        local names name cmd args envkeys typ
        names=$(jq -r '
            (.mcpServers // {}) | to_entries[] | .key
        ' "$file" 2>/dev/null) || return 0
        while IFS= read -r name; do
            [[ -n "$name" ]] || continue
            cmd=$(jq -r --arg n "$name" '.mcpServers[$n].command // .mcpServers[$n].url // ""' "$file" 2>/dev/null)
            args=$(jq -r --arg n "$name" '(.mcpServers[$n].args // []) | join(" ")' "$file" 2>/dev/null)
            envkeys=$(jq -r --arg n "$name" '(.mcpServers[$n].env // {}) | keys | join(", ")' "$file" 2>/dev/null)
            typ=$(jq -r --arg n "$name" '.mcpServers[$n].type // "stdio"' "$file" 2>/dev/null)
            local tagged_name="${name}(${source_label})"
            if [[ " ${MCP_NAMES[*]} " != *" $tagged_name "* ]]; then
                MCP_NAMES+=("$tagged_name")
                MCP_CMDS[$tagged_name]="$(redact_value command "$cmd")"
                MCP_ARGS[$tagged_name]="$(redact_value args "$args")"
                MCP_ENVKEYS[$tagged_name]="$envkeys"
                MCP_TYPE[$tagged_name]="$typ"

                add_finding "REVIEW" "MCP Servers" "MCP server configured: $name" "source=$source_label; type=${typ:-stdio}; command=${cmd:-unknown}; env_keys=${envkeys:-none}"
                local env_risks
                env_risks="$(mcp_env_risk_tags "$envkeys")"
                [[ -n "$env_risks" ]] && add_finding "REVIEW" "MCP Servers" "MCP server env keys imply elevated scope: $name" "$env_risks"
                local base_cmd
                base_cmd="$(basename "$cmd" 2>/dev/null)"
                for hint in ${(z)DANGEROUS_MCP_HINTS}; do
                    [[ "$base_cmd" == "$hint" ]] && add_finding "WARN" "MCP Servers" "MCP server uses command-capable runtime: $name" "$cmd"
                done
            fi
        done <<< "$names"
    fi
}

collect_config() {
    local cfg="$HOME_DIR/.claude.json"
    if [[ ! -f "$cfg" ]]; then
        add_finding "INFO" "Config" ".claude.json not found" "$cfg"
        return 0
    fi

    local mode
    mode=$(file_mode "$cfg")
    SENSITIVE_FILES+=(".claude.json|$mode|$cfg")
    [[ -n "$mode" && "$mode" != "600" && "$mode" != "400" ]] && add_finding "REVIEW" "Config" ".claude.json is readable beyond the owner" "mode=$mode"

    if [[ "$HAS_JQ" != "true" ]]; then
        add_finding "INFO" "Config" "jq not found; skipping .claude.json deep parse"
        return 0
    fi

    # Model
    local model
    model=$(jq -r '.model // ""' "$cfg" 2>/dev/null)
    [[ -n "$model" ]] && add_finding "INFO" "Config" "Default model: $model"

    # userID
    local uid
    uid=$(jq -r '.userID // ""' "$cfg" 2>/dev/null)
    [[ -n "$uid" ]] && add_finding "INFO" "Config" "User ID present" "${uid:0:16}..."

    # Projects
    local proj_paths trust_accepted allowed_tools
    proj_paths=$(jq -r '(.projects // {}) | keys[]' "$cfg" 2>/dev/null)
    while IFS= read -r proj; do
        [[ -n "$proj" ]] || continue
        trust_accepted=$(jq -r --arg p "$proj" '.projects[$p].hasTrustDialogAccepted // false' "$cfg" 2>/dev/null)
        allowed_tools=$(jq -r --arg p "$proj" '(.projects[$p].allowedTools // []) | join(", ")' "$cfg" 2>/dev/null)
        local enabled_mcp disabled_mcp
        enabled_mcp=$(jq -r --arg p "$proj" '(.projects[$p].enabledMcpjsonServers // []) | join(", ")' "$cfg" 2>/dev/null)
        disabled_mcp=$(jq -r --arg p "$proj" '(.projects[$p].disabledMcpjsonServers // []) | join(", ")' "$cfg" 2>/dev/null)
        PROJECTS+=("$proj|trust=$trust_accepted|tools=${allowed_tools:-none}|mcp_enabled=${enabled_mcp:-none}|mcp_disabled=${disabled_mcp:-none}")
        if [[ "$trust_accepted" == "true" ]]; then
            add_finding "WARN" "Projects" "Trusted project grants Claude Code broader workspace autonomy" "$proj"
        fi
        if [[ -n "$allowed_tools" ]]; then
            add_finding "REVIEW" "Projects" "Project has pre-approved tools: $(basename "$proj")" "$allowed_tools"
            ALLOWED_TOOLS+=("$proj|$allowed_tools")
        fi
        if [[ -n "$enabled_mcp" ]]; then
            add_finding "INFO" "Projects" "Project has enabled MCP .json servers: $(basename "$proj")" "$enabled_mcp"
        fi
    done <<< "$proj_paths"
    ((${#PROJECTS[@]} > 0)) && add_finding "INFO" "Projects" "${#PROJECTS[@]} project(s) in config"

    # Bypass permissions gate
    local bypass_accounts
    bypass_accounts=$(jq -r '
        (.bypassPermissionsGateByAccount // {}) | to_entries[] | select(.value == true) | .key
    ' "$cfg" 2>/dev/null)
    if [[ -n "$bypass_accounts" ]]; then
        while IFS= read -r acct; do
            [[ -n "$acct" ]] && add_finding "WARN" "Permissions" "Bypass permissions gate is ENABLED for account" "$acct"
        done <<< "$bypass_accounts"
    fi

    # Plugin usage
    local plugin_count
    plugin_count=$(jq -r '(.pluginUsage // {}) | length' "$cfg" 2>/dev/null)
    ((plugin_count > 0)) && add_finding "INFO" "Skills" "$plugin_count skill/plugin package(s) referenced in usage history"
}

collect_settings() {
    # Global Claude Code settings: ~/.claude/settings.json
    local gsettings="$CLAUDE_DIR/settings.json"
    if [[ -f "$gsettings" ]]; then
        local mode
        mode=$(file_mode "$gsettings")
        SENSITIVE_FILES+=("settings.json (global)|$mode|$gsettings")
        [[ -n "$mode" && "$mode" != "600" && "$mode" != "400" ]] && add_finding "REVIEW" "Config" "Global settings.json is readable beyond the owner" "mode=$mode"
        collect_settings_from_file "$gsettings" "global"
    fi

    # Local settings: ~/.claude/settings.local.json
    local lsettings="$CLAUDE_DIR/settings.local.json"
    if [[ -f "$lsettings" ]]; then
        local mode
        mode=$(file_mode "$lsettings")
        SENSITIVE_FILES+=("settings.local.json|$mode|$lsettings")
        collect_settings_from_file "$lsettings" "global-local"
    fi
}

collect_settings_from_file() {
    local file="$1" label="$2"
    [[ -r "$file" ]] || return 0
    [[ "$HAS_JQ" != "true" ]] && return 0

    # MCP servers
    parse_mcp_servers_from_json "$file" "$label"

    # Hooks
    local hook_events event cmd risk
    hook_events=$(jq -r '(.hooks // {}) | keys[]' "$file" 2>/dev/null)
    while IFS= read -r event; do
        [[ -n "$event" ]] || continue
        local hook_cmds
        hook_cmds=$(jq -r --arg e "$event" '
            .hooks[$e][]? |
            if type == "object" then
                (.hooks[]? | if type == "object" then .command // "" elif type == "string" then . else "" end),
                (if type == "string" then . else "" end)
            elif type == "string" then .
            else "" end
        ' "$file" 2>/dev/null | grep -v '^$')
        if [[ -z "$hook_cmds" ]]; then
            hook_cmds=$(jq -r --arg e "$event" '.hooks[$e][] | .command // (if type == "string" then . else "" end)' "$file" 2>/dev/null | grep -v '^$')
        fi
        if [[ -n "$hook_cmds" ]]; then
            while IFS= read -r cmd; do
                [[ -n "$cmd" ]] || continue
                risk="$(hook_risk_tags "$cmd")"
                HOOKS+=("$event|$label|$cmd|$risk")
                add_finding "REVIEW" "Hooks" "Hook configured: $event" "source=$label; cmd=${cmd:0:80}${risk:+; risk=$risk}"
                [[ -n "$risk" ]] && add_finding "WARN" "Hooks" "Hook has elevated risk: $event" "risk=$risk; cmd=${cmd:0:80}"
            done <<< "$hook_cmds"
        else
            HOOKS+=("$event|$label|(configured)|")
            add_finding "REVIEW" "Hooks" "Hook configured: $event" "source=$label"
        fi
    done <<< "$hook_events"

    # Permissions
    local allowed_tools banned_tools
    allowed_tools=$(jq -r '(.permissions.allow // []) | join(", ")' "$file" 2>/dev/null)
    banned_tools=$(jq -r '(.permissions.deny // []) | join(", ")' "$file" 2>/dev/null)
    if [[ -n "$allowed_tools" ]]; then
        add_finding "REVIEW" "Permissions" "Pre-approved tools in settings ($label)" "$allowed_tools"
    fi
    if [[ -n "$banned_tools" ]]; then
        add_finding "INFO" "Permissions" "Denied tools in settings ($label)" "$banned_tools"
    fi

    # Model override
    local model
    model=$(jq -r '.model // ""' "$file" 2>/dev/null)
    [[ -n "$model" ]] && add_finding "INFO" "Config" "Model override in settings ($label): $model"
}

collect_project_settings() {
    # Find per-project .claude/settings.json files
    local proj_dir proj_settings proj_local
    if [[ "$HAS_JQ" == "true" ]]; then
        local proj_paths
        proj_paths=$(jq -r '(.projects // {}) | keys[]' "$HOME_DIR/.claude.json" 2>/dev/null)
        while IFS= read -r proj; do
            [[ -n "$proj" && -d "$proj" ]] || continue
            proj_settings="$proj/.claude/settings.json"
            proj_local="$proj/.claude/settings.local.json"
            [[ -f "$proj_settings" ]] && collect_settings_from_file "$proj_settings" "project:$(basename "$proj")"
            [[ -f "$proj_local" ]] && collect_settings_from_file "$proj_local" "project-local:$(basename "$proj")"
            # Also check for .mcp.json
            local mcp_json="$proj/.mcp.json"
            [[ -f "$mcp_json" ]] && parse_mcp_servers_from_json "$mcp_json" "project-mcp:$(basename "$proj")"
        done <<< "$proj_paths"
    fi
}

collect_desktop_config() {
    local app_support="$HOME_DIR/Library/Application Support/Claude"
    local desktop_cfg="$app_support/claude_desktop_config.json"
    [[ -f "$desktop_cfg" ]] || return 0

    local mode
    mode=$(file_mode "$desktop_cfg")
    SENSITIVE_FILES+=("claude_desktop_config.json|$mode|$desktop_cfg")

    [[ "$HAS_JQ" != "true" ]] && return 0

    # Desktop MCP servers
    parse_mcp_servers_from_json "$desktop_cfg" "desktop"

    # Bypass permissions gate
    local bypass
    bypass=$(jq -r '
        (.preferences.bypassPermissionsGateByAccount // {}) | to_entries[] | select(.value == true) | .key
    ' "$desktop_cfg" 2>/dev/null)
    if [[ -n "$bypass" ]]; then
        while IFS= read -r acct; do
            [[ -n "$acct" ]] && add_finding "WARN" "Permissions" "Desktop: bypass permissions gate ENABLED for account" "$acct"
        done <<< "$bypass"
    fi

    # Cowork settings
    local cowork_web_search cowork_scheduled hipaa_restricted
    cowork_web_search=$(jq -r '.preferences.coworkWebSearchEnabled // false' "$desktop_cfg" 2>/dev/null)
    cowork_scheduled=$(jq -r '.preferences.coworkScheduledTasksEnabled // false' "$desktop_cfg" 2>/dev/null)
    hipaa_restricted=$(jq -r '.preferences.coworkHipaaRestricted // false' "$desktop_cfg" 2>/dev/null)
    add_finding "INFO" "Desktop" "Cowork web search enabled: $cowork_web_search"
    [[ "$cowork_scheduled" == "true" ]] && add_finding "REVIEW" "Desktop" "Cowork scheduled tasks are enabled"
    [[ "$hipaa_restricted" == "true" ]] && add_finding "INFO" "Desktop" "HIPAA-restricted mode is active"

    # coworkUserFilesPath
    local files_path
    files_path=$(jq -r '.coworkUserFilesPath // ""' "$desktop_cfg" 2>/dev/null)
    [[ -n "$files_path" ]] && add_finding "INFO" "Desktop" "Cowork user files path" "$files_path"
}

collect_sensitive_files() {
    local p mode
    local app_support="$HOME_DIR/Library/Application Support/Claude"

    for p in "$app_support/config.json" "$app_support/buddy-tokens.json"; do
        [[ -e "$p" ]] || continue
        mode=$(file_mode "$p")
        local fname
        fname="$(basename "$p")"
        SENSITIVE_FILES+=("$fname|$mode|$p")
        if [[ "$fname" == "config.json" && "$mode" != "600" && "$mode" != "400" ]]; then
            add_finding "WARN" "Sensitive Files" "config.json permissions are broader than owner-only" "mode=$mode; path=$p"
        elif [[ "$fname" == "buddy-tokens.json" ]]; then
            add_finding "REVIEW" "Sensitive Files" "buddy-tokens.json present (may contain auth tokens)" "mode=$mode"
        else
            add_finding "INFO" "Sensitive Files" "$fname present" "mode=$mode"
        fi
    done

    # ant-did (device identity)
    local ant_did="$app_support/ant-did"
    if [[ -f "$ant_did" ]]; then
        mode=$(file_mode "$ant_did")
        SENSITIVE_FILES+=("ant-did|$mode|$ant_did")
        add_finding "INFO" "Sensitive Files" "ant-did (device identity) present" "mode=$mode"
    fi

    # Check for credentials in backups
    local backup_dir="$CLAUDE_DIR/backups"
    if [[ -d "$backup_dir" ]]; then
        local backup_count
        backup_count=$(dir_file_count "$backup_dir")
        local backup_bytes
        backup_bytes=$(dir_total_bytes "$backup_dir")
        add_finding "INFO" "Sensitive Files" "backups directory contains $backup_count file(s)" "size=$(fmt_bytes "$backup_bytes")"
    fi
}

collect_retention() {
    local name dir count bytes latest
    for name in sessions shell-snapshots session-env projects; do
        dir="$CLAUDE_DIR/$name"
        [[ -d "$dir" ]] || continue
        count="$(dir_file_count "$dir")"
        bytes="$(dir_total_bytes "$dir")"
        latest="$(dir_latest_mtime "$dir")"
        RETENTION_ITEMS+=("$name|$count|$bytes|$latest|$dir")
        add_finding "INFO" "Retention" "$name contains $count file(s)" "size=$(fmt_bytes "$bytes"); latest=${latest:-none}"
        ((bytes > 104857600)) && add_finding "REVIEW" "Retention" "$name retained data is larger than 100 MB" "$(fmt_bytes "$bytes")"
        ((count > 1000)) && add_finding "REVIEW" "Retention" "$name contains more than 1000 files" "$count files"
    done

    # Cowork / Claude user files
    local app_support="$HOME_DIR/Library/Application Support/Claude"
    local cowork_path
    if [[ "$HAS_JQ" == "true" && -f "$app_support/claude_desktop_config.json" ]]; then
        cowork_path=$(jq -r '.coworkUserFilesPath // ""' "$app_support/claude_desktop_config.json" 2>/dev/null)
    fi
    if [[ -n "$cowork_path" && -d "$cowork_path" ]]; then
        count="$(dir_file_count "$cowork_path")"
        bytes="$(dir_total_bytes "$cowork_path")"
        latest="$(dir_latest_mtime "$cowork_path")"
        RETENTION_ITEMS+=("cowork-user-files|$count|$bytes|$latest|$cowork_path")
        add_finding "INFO" "Retention" "Cowork user files: $count file(s)" "size=$(fmt_bytes "$bytes"); latest=${latest:-none}"
        ((bytes > 524288000)) && add_finding "REVIEW" "Retention" "Cowork user files directory is larger than 500 MB" "$(fmt_bytes "$bytes")"
    fi

    # App Support session data
    for name in claude-code-sessions local-agent-mode-sessions; do
        dir="$app_support/$name"
        [[ -d "$dir" ]] || continue
        count="$(dir_file_count "$dir")"
        bytes="$(dir_total_bytes "$dir")"
        latest="$(dir_latest_mtime "$dir")"
        RETENTION_ITEMS+=("$name|$count|$bytes|$latest|$dir")
        add_finding "INFO" "Retention" "$name contains $count file(s)" "size=$(fmt_bytes "$bytes"); latest=${latest:-none}"
    done
}

collect_runtime() {
    local out count line la_dir plist crons

    # Active Claude Code sessions via ~/.claude/sessions/
    local sess_dir="$CLAUDE_DIR/sessions"
    if [[ -d "$sess_dir" ]]; then
        local sess_file
        for sess_file in "$sess_dir"/*.json; do
            [[ -r "$sess_file" ]] || continue
            if [[ "$HAS_JQ" == "true" ]]; then
                local sess_pid sess_cwd sess_ver sess_kind sess_started
                sess_pid=$(jq -r '.pid // ""' "$sess_file" 2>/dev/null)
                sess_cwd=$(jq -r '.cwd // ""' "$sess_file" 2>/dev/null)
                sess_ver=$(jq -r '.version // ""' "$sess_file" 2>/dev/null)
                sess_kind=$(jq -r '.kind // ""' "$sess_file" 2>/dev/null)
                ACTIVE_SESSIONS+=("${sess_pid:-?}|${sess_kind:-unknown}|${sess_ver:-?}|${sess_cwd:-?}")
                if [[ -n "$sess_pid" ]] && kill -0 "$sess_pid" 2>/dev/null; then
                    add_finding "INFO" "Runtime" "Active Claude Code session (pid $sess_pid)" "kind=${sess_kind:-?}; version=${sess_ver:-?}; cwd=$(display_text "${sess_cwd:-?}")"
                else
                    add_finding "INFO" "Runtime" "Stale session record (pid ${sess_pid:-?} not running)" "$(basename "$sess_file")"
                fi
            fi
        done
    fi

    # Processes
    out=$(pgrep -fl 'Claude|claude' 2>/dev/null | grep -i 'claude\|anthropic') || true
    if [[ -n "$out" ]]; then
        count=$(printf '%s\n' "$out" | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')
        add_finding "INFO" "Runtime" "Claude-related process(es) running: $count"
    fi

    # LaunchAgents
    la_dir="$HOME_DIR/Library/LaunchAgents"
    for plist in "$la_dir"/*claude* "$la_dir"/*Claude* "$la_dir"/*anthropic* "$la_dir"/*Anthropic*; do
        [[ -e "$plist" ]] || continue
        add_finding "WARN" "Runtime" "Claude-related LaunchAgent found" "$(basename "$plist")"
    done

    # Crontab
    crons=$(crontab -l 2>/dev/null) || true
    if [[ -n "$crons" ]]; then
        while IFS= read -r line; do
            [[ "${(L)line}" == *claude* || "${(L)line}" == *anthropic* ]] && add_finding "WARN" "Runtime" "Claude-related crontab entry found" "$line"
        done <<< "$crons"
    fi
}

print_table_line() {
    printf '  %-22s %s\n' "$1" "$2"
}

render_terminal() {
    print -r -- ""
    print -r -- "CLAUDE-AUDIT v$VERSION - Claude Code local security audit"
    print -r -- "User: $(display_text "$AUDIT_USER")"
    print -r -- "Claude home: $(display_text "$CLAUDE_DIR")"
    print -r -- "Findings: WARN=$WARN_COUNT REVIEW=$REVIEW_COUNT INFO=$INFO_COUNT"
    print -r -- ""

    if [[ "$OPT_QUIET" != "true" || $WARN_COUNT -gt 0 || $REVIEW_COUNT -gt 0 ]]; then
        print -r -- "Findings"
        for ((i=0; i<${#FINDING_SEV[@]}; i++)); do
            [[ "$OPT_QUIET" == "true" && "${FINDING_SEV[$i]}" == "INFO" ]] && continue
            printf '  [%s] %-16s %s\n' "${FINDING_SEV[$i]}" "${FINDING_SECT[$i]}" "$(display_text "${FINDING_MSG[$i]}")"
            [[ -n "${FINDING_DET[$i]}" ]] && printf '       %s\n' "$(display_text "${FINDING_DET[$i]}")"
        done
        print -r -- ""
    fi

    print -r -- "MCP Servers"
    if ((${#MCP_NAMES[@]} == 0)); then
        print -r -- "  none"
    else
        for name in "${MCP_NAMES[@]}"; do
            print_table_line "$name" "$(display_text "type=${MCP_TYPE[$name]:-stdio} cmd=${MCP_CMDS[$name]:-unknown} env=${MCP_ENVKEYS[$name]:-none}")"
        done
    fi
    print -r -- ""

    print -r -- "Projects"
    if ((${#PROJECTS[@]} == 0)); then print -r -- "  none"; else
        for row in "${PROJECTS[@]}"; do
            local proj_name="${row%%|*}" rest="${row#*|}"
            print_table_line "$(display_text "$(basename "$proj_name")")" "$(display_text "$rest")"
        done
    fi
    print -r -- ""

    print -r -- "Hooks"
    if ((${#HOOKS[@]} == 0)); then print -r -- "  none"; else
        for row in "${HOOKS[@]}"; do
            local event="${row%%|*}" rest="${row#*|}"
            print_table_line "$event" "$(display_text "$rest")"
        done
    fi
    print -r -- ""

    print -r -- "Active Sessions"
    if ((${#ACTIVE_SESSIONS[@]} == 0)); then print -r -- "  none"; else
        for row in "${ACTIVE_SESSIONS[@]}"; do
            local pid="${row%%|*}" rest="${row#*|}"
            print_table_line "pid=$pid" "$(display_text "$rest")"
        done
    fi
    print -r -- ""

    print -r -- "Sensitive Files"
    if ((${#SENSITIVE_FILES[@]} == 0)); then print -r -- "  none"; else
        for row in "${SENSITIVE_FILES[@]}"; do
            local n="${row%%|*}" rest="${row#*|}"
            print_table_line "$n" "$(display_text "$rest")"
        done
    fi
    print -r -- ""

    print -r -- "Retention"
    if ((${#RETENTION_ITEMS[@]} == 0)); then print -r -- "  none"; else
        for row in "${RETENTION_ITEMS[@]}"; do
            local n="${row%%|*}" rest="${row#*|}"
            print_table_line "$n" "$(display_text "$rest")"
        done
    fi
    print -r -- ""
}

render_summary_terminal() {
    printf '%s  WARN=%d REVIEW=%d INFO=%d  %s\n' "$(display_text "$AUDIT_USER")" "$WARN_COUNT" "$REVIEW_COUNT" "$INFO_COUNT" "$(display_text "$CLAUDE_DIR")"
    local i shown=0
    for ((i=0; i<${#FINDING_SEV[@]}; i++)); do
        [[ "${FINDING_SEV[$i]}" == "INFO" ]] && continue
        printf '  [%s] %s: %s\n' "${FINDING_SEV[$i]}" "${FINDING_SECT[$i]}" "$(display_text "${FINDING_MSG[$i]}")"
        ((shown++))
        ((shown >= 8)) && break
    done
}

json_split_field() {
    local row="$1" n="$2" rest="$row" part i
    for ((i=1; i<n; i++)); do
        part="${rest%%|*}"
        rest="${rest#*|}"
    done
    printf '%s' "${rest%%|*}"
}

render_json() {
    local findings="[" idx=0
    for ((i=0; i<${#FINDING_SEV[@]}; i++)); do
        ((idx > 0)) && findings+=","
        findings+="{\"severity\":$(jstr "${FINDING_SEV[$i]}"),\"section\":$(jstr "${FINDING_SECT[$i]}"),\"message\":$(jstr_out "${FINDING_MSG[$i]}"),\"detail\":$(jstr_out "${FINDING_DET[$i]}")}"
        ((idx++))
    done
    findings+="]"

    local mcp="["
    idx=0
    for name in "${MCP_NAMES[@]}"; do
        ((idx > 0)) && mcp+=","
        mcp+="{\"name\":$(jstr_out "$name"),\"type\":$(jstr "${MCP_TYPE[$name]:-stdio}"),\"command\":$(jstr_out "${MCP_CMDS[$name]:-}"),\"args\":$(jstr_out "${MCP_ARGS[$name]:-}"),\"env_keys\":$(jstr "${MCP_ENVKEYS[$name]:-}"),\"env_risk_tags\":$(jstr "$(mcp_env_risk_tags "${MCP_ENVKEYS[$name]:-}")")}"
        ((idx++))
    done
    mcp+="]"

    local projects="[" idx=0
    for row in "${PROJECTS[@]}"; do
        ((idx > 0)) && projects+=","
        projects+="{\"path\":$(jstr_out "$(json_split_field "$row" 1)"),\"detail\":$(jstr_out "${row#*|}")}"
        ((idx++))
    done
    projects+="]"

    local hooks="[" idx=0
    for row in "${HOOKS[@]}"; do
        ((idx > 0)) && hooks+=","
        hooks+="{\"event\":$(jstr "$(json_split_field "$row" 1)"),\"source\":$(jstr "$(json_split_field "$row" 2)"),\"command\":$(jstr_out "$(json_split_field "$row" 3)"),\"risk_tags\":$(jstr "$(json_split_field "$row" 4)")}"
        ((idx++))
    done
    hooks+="]"

    local sessions="[" idx=0
    for row in "${ACTIVE_SESSIONS[@]}"; do
        ((idx > 0)) && sessions+=","
        sessions+="{\"pid\":$(jstr "$(json_split_field "$row" 1)"),\"kind\":$(jstr "$(json_split_field "$row" 2)"),\"version\":$(jstr "$(json_split_field "$row" 3)"),\"cwd\":$(jstr_out "$(json_split_field "$row" 4)")}"
        ((idx++))
    done
    sessions+="]"

    local sens_files="[" idx=0
    for row in "${SENSITIVE_FILES[@]}"; do
        ((idx > 0)) && sens_files+=","
        sens_files+="{\"name\":$(jstr "$(json_split_field "$row" 1)"),\"mode\":$(jstr "$(json_split_field "$row" 2)"),\"path\":$(jstr_out "$(json_split_field "$row" 3)")}"
        ((idx++))
    done
    sens_files+="]"

    local retention="[" idx=0
    for row in "${RETENTION_ITEMS[@]}"; do
        ((idx > 0)) && retention+=","
        retention+="{\"name\":$(jstr "$(json_split_field "$row" 1)"),\"file_count\":$(jstr "$(json_split_field "$row" 2)"),\"bytes\":$(jstr "$(json_split_field "$row" 3)"),\"latest_mtime\":$(jstr "$(json_split_field "$row" 4)"),\"path\":$(jstr_out "$(json_split_field "$row" 5)")}"
        ((idx++))
    done
    retention+="]"

    printf '{"timestamp":%s,"hostname":%s,"username":%s,"claude_dir":%s,"summary":{"warn":%d,"review":%d,"info":%d},"findings":%s,"mcp_servers":%s,"projects":%s,"hooks":%s,"active_sessions":%s,"sensitive_files":%s,"retention":%s}' \
        "$(jstr "$TIMESTAMP")" "$(jstr "$HOSTNAME_VAL")" "$(jstr_out "$AUDIT_USER")" "$(jstr_out "$CLAUDE_DIR")" \
        "$WARN_COUNT" "$REVIEW_COUNT" "$INFO_COUNT" "$findings" "$mcp" \
        "$projects" "$hooks" "$sessions" "$sens_files" "$retention"
}

html_rows_findings() {
    local i
    for ((i=0; i<${#FINDING_SEV[@]}; i++)); do
        [[ "$OPT_QUIET" == "true" && "${FINDING_SEV[$i]}" == "INFO" ]] && continue
        printf '<tr><td><span class="badge %s">%s</span></td><td>%s</td><td>%s</td><td><code>%s</code></td></tr>\n' \
            "$(html_escape "${(L)FINDING_SEV[$i]}")" "$(html_escape "${FINDING_SEV[$i]}")" "$(html_escape "${FINDING_SECT[$i]}")" "$(html_out "${FINDING_MSG[$i]}")" "$(html_out "${FINDING_DET[$i]}")"
    done
}

html_list_rows() {
    local title="$1"
    shift
    printf '<h2>%s</h2>\n<table><tbody>\n' "$(html_escape "$title")"
    local row first rest
    if (($# == 0)); then
        print -r -- '<tr><td>none</td><td></td></tr>'
    else
        for row in "$@"; do
            first="${row%%|*}"
            rest="${row#*|}"
            printf '<tr><td>%s</td><td><code>%s</code></td></tr>\n' "$(html_out "$first")" "$(html_out "$rest")"
        done
    fi
    print -r -- '</tbody></table>'
}

render_html_body() {
    cat <<EOF
<section class="report">
<h1>CLAUDE-AUDIT</h1>
<p class="meta">User: <strong>$(html_out "$AUDIT_USER")</strong> · Host: <strong>$(html_escape "$HOSTNAME_VAL")</strong> · Generated: <strong>$(html_escape "$TIMESTAMP")</strong></p>
<p class="meta">Claude home: <code>$(html_out "$CLAUDE_DIR")</code></p>
<div class="summary">
  <div><span>WARN</span><strong>$WARN_COUNT</strong></div>
  <div><span>REVIEW</span><strong>$REVIEW_COUNT</strong></div>
  <div><span>INFO</span><strong>$INFO_COUNT</strong></div>
</div>
<h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>Section</th><th>Finding</th><th>Detail</th></tr></thead><tbody>
EOF
    html_rows_findings
    cat <<EOF
</tbody></table>
<h2>MCP Servers</h2>
<table><thead><tr><th>Name</th><th>Type</th><th>Command</th><th>Env Keys</th></tr></thead><tbody>
EOF
    if ((${#MCP_NAMES[@]} == 0)); then
        print -r -- '<tr><td>none</td><td></td><td></td><td></td></tr>'
    else
        local name
        for name in "${MCP_NAMES[@]}"; do
            printf '<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td><code>%s</code></td></tr>\n' \
                "$(html_out "$name")" "$(html_escape "${MCP_TYPE[$name]:-stdio}")" "$(html_out "${MCP_CMDS[$name]:-}")" "$(html_escape "${MCP_ENVKEYS[$name]:-}")"
        done
    fi
    print -r -- '</tbody></table>'
    html_list_rows "Projects" "${PROJECTS[@]}"
    html_list_rows "Hooks" "${HOOKS[@]}"
    html_list_rows "Active Sessions" "${ACTIVE_SESSIONS[@]}"
    html_list_rows "Sensitive Files" "${SENSITIVE_FILES[@]}"
    html_list_rows "Retention" "${RETENTION_ITEMS[@]}"
    print -r -- '</section>'
}

render_html_doc_start() {
    cat <<'EOF'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CLAUDE-AUDIT Report</title>
<style>
body{margin:0;background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{max-width:1180px;margin:0 auto;padding:32px 20px}
h1{margin:0 0 8px;font-size:28px}
h2{margin:28px 0 10px;font-size:18px}
.report{border-top:1px solid #21262d;padding:24px 0}
.meta{color:#8b949e;margin:4px 0}
code{color:#cae8ff;white-space:pre-wrap;word-break:break-word}
.summary{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin:20px 0}
.summary div{background:#161b22;border:1px solid #21262d;border-radius:6px;padding:12px}
.summary span{display:block;color:#8b949e;font-size:12px}
.summary strong{font-size:24px}
table{width:100%;border-collapse:collapse;background:#0d1117;border:1px solid #21262d}
th,td{padding:9px 10px;border-bottom:1px solid #21262d;text-align:left;vertical-align:top;font-size:13px}
th{color:#8b949e;background:#161b22}
.badge{display:inline-block;border-radius:4px;padding:2px 6px;font-weight:700;font-size:12px}
.warn{background:#5c1f1f;color:#ffa198}.review{background:#3d2f00;color:#f0c846}.info{background:#0c2a4a;color:#79c0ff}
</style>
</head>
<body><main>
EOF
}

render_html_doc_end() {
    print -r -- '</main></body></html>'
}

render_json_for_users() {
    if ((${#USERS[@]} == 1)); then
        audit_one_user "${USERS[0]}"
        render_json
    else
        printf '['
        for ((ui=0; ui<${#USERS[@]}; ui++)); do
            ((ui > 0)) && printf ','
            audit_one_user "${USERS[$ui]}"
            render_json
        done
        printf ']'
    fi
}

render_summary_json_for_users() {
    if ((${#USERS[@]} == 1)); then
        audit_one_user "${USERS[0]}"
        printf '{"timestamp":%s,"hostname":%s,"username":%s,"claude_dir":%s,"summary":{"warn":%d,"review":%d,"info":%d}}\n' \
            "$(jstr "$TIMESTAMP")" "$(jstr "$HOSTNAME_VAL")" "$(jstr_out "$AUDIT_USER")" "$(jstr_out "$CLAUDE_DIR")" "$WARN_COUNT" "$REVIEW_COUNT" "$INFO_COUNT"
    else
        printf '['
        for ((ui=0; ui<${#USERS[@]}; ui++)); do
            ((ui > 0)) && printf ','
            audit_one_user "${USERS[$ui]}"
            printf '{"timestamp":%s,"hostname":%s,"username":%s,"claude_dir":%s,"summary":{"warn":%d,"review":%d,"info":%d}}' \
                "$(jstr "$TIMESTAMP")" "$(jstr "$HOSTNAME_VAL")" "$(jstr_out "$AUDIT_USER")" "$(jstr_out "$CLAUDE_DIR")" "$WARN_COUNT" "$REVIEW_COUNT" "$INFO_COUNT"
        done
        printf ']\n'
    fi
}

usage() {
    print -r -- "CLAUDE-AUDIT v$VERSION - Claude Code local security audit"
    print -r -- "Usage: $SCRIPT_NAME [--html [FILE]] [--json] [--summary] [--output FILE] [--fail-on warn|review] [--redact-paths] [--user USER] [--all-users] [--claude-dir DIR] [-q|--quiet] [--version] [-h|--help]"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --json) OPT_JSON=true ;;
        --fail-on) shift; OPT_FAIL_ON="${1:-}" ;;
        --output) shift; OPT_OUTPUT="${1:-}" ;;
        --summary) OPT_SUMMARY=true ;;
        --claude-dir) shift; OPT_CLAUDE_DIR="${1:-}" ;;
        --redact-paths) OPT_REDACT_PATHS=true ;;
        --html)
            if [[ -n "${2:-}" && "$2" != -* ]]; then
                OPT_HTML="$2"
                shift
            else
                OPT_HTML="AUTO"
            fi
            ;;
        -q|--quiet) OPT_QUIET=true ;;
        --user) shift; AUDIT_USER="${1:-}" ;;
        --all-users) OPT_ALL_USERS=true ;;
        --version) print -r -- "CLAUDE-AUDIT v$VERSION"; exit 0 ;;
        -h|--help) usage; exit 0 ;;
        *) print -r -- "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
    shift
done

preflight

if [[ "$OPT_JSON" == "true" && -n "$OPT_HTML" ]]; then
    print -r -- "Error: --json and --html are mutually exclusive" >&2
    exit 1
fi
if [[ "$OPT_ALL_USERS" == "true" && -n "$AUDIT_USER" ]]; then
    print -r -- "Error: --user and --all-users are mutually exclusive" >&2
    exit 1
fi
if [[ -n "$OPT_CLAUDE_DIR" && "$OPT_ALL_USERS" == "true" ]]; then
    print -r -- "Error: --claude-dir and --all-users are mutually exclusive" >&2
    exit 1
fi
if [[ -n "$OPT_CLAUDE_DIR" && ! -d "$OPT_CLAUDE_DIR" ]]; then
    print -r -- "Error: --claude-dir does not exist: $OPT_CLAUDE_DIR" >&2
    exit 1
fi
if [[ -z "$OPT_HTML" && -n "$OPT_OUTPUT" && "$OPT_OUTPUT" == *.html ]]; then
    print -r -- "Error: --output .html requires --html" >&2
    exit 1
fi
case "$OPT_FAIL_ON" in
    ""|warn|review) ;;
    *) print -r -- "Error: --fail-on must be 'warn' or 'review'" >&2; exit 1 ;;
esac

audit_one_user() {
    local user="$1"
    reset_state
    AUDIT_USER="$user"
    HOME_DIR="$(get_user_home "$AUDIT_USER")"
    if [[ -z "$HOME_DIR" || ! -d "$HOME_DIR" ]]; then
        add_finding "WARN" "General" "Unable to resolve home directory" "$AUDIT_USER"
        CLAUDE_DIR=""
        return 0
    fi

    if [[ -n "$OPT_CLAUDE_DIR" ]]; then
        CLAUDE_DIR="$OPT_CLAUDE_DIR"
        HOME_DIR="${CLAUDE_DIR:h}"
    else
        CLAUDE_DIR="$HOME_DIR/$CLAUDE_DIR_NAME"
    fi
    TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    HOSTNAME_VAL="$(hostname)"

    if [[ ! -d "$CLAUDE_DIR" && ! -f "$HOME_DIR/.claude.json" ]]; then
        add_finding "INFO" "General" "Claude Code data not found" "$CLAUDE_DIR"
    else
        collect_config
        collect_settings
        collect_project_settings
        collect_desktop_config
        collect_sensitive_files
        collect_retention
        collect_runtime
    fi
}

USERS=()
if [[ "$OPT_ALL_USERS" == "true" ]]; then
    USERS=("${(@f)$(discover_claude_users)}")
    if ((${#USERS[@]} == 0)); then
        print -r -- "No users with Claude Code data found." >&2
        exit 1
    fi
else
    [[ -z "$AUDIT_USER" ]] && AUDIT_USER="$(id -un)"
    USERS=("$AUDIT_USER")
fi

FINAL_EXIT=0
apply_fail_on() {
    [[ -z "$OPT_FAIL_ON" ]] && return 0
    if [[ "$OPT_FAIL_ON" == "warn" && "$WARN_COUNT" -gt 0 ]]; then
        FINAL_EXIT=2
    elif [[ "$OPT_FAIL_ON" == "review" && "$REVIEW_COUNT" -gt 0 && "$FINAL_EXIT" -eq 0 ]]; then
        FINAL_EXIT=1
    fi
}

run_output() {
    if [[ "$OPT_JSON" == "true" ]]; then
        if [[ "$OPT_SUMMARY" == "true" ]]; then
            render_summary_json_for_users
        else
            render_json_for_users
            print -r -- ""
        fi
    elif [[ -n "$OPT_HTML" ]]; then
        render_html_doc_start
        for user in "${USERS[@]}"; do
            audit_one_user "$user"
            render_html_body
        done
        render_html_doc_end
    else
        for user in "${USERS[@]}"; do
            audit_one_user "$user"
            if [[ "$OPT_SUMMARY" == "true" ]]; then
                render_summary_terminal
            else
                render_terminal
            fi
            apply_fail_on
        done
    fi
}

if [[ -n "$OPT_HTML" ]]; then
    local_html_file="${OPT_OUTPUT:-$OPT_HTML}"
    if [[ "$local_html_file" == "AUTO" ]]; then
        local_html_file="claude_audit_$(date '+%Y%m%d_%H%M%S').html"
    fi
    umask 077
    run_output > "$local_html_file"
    print -r -- "HTML report written: $local_html_file"
elif [[ -n "$OPT_OUTPUT" ]]; then
    run_output > "$OPT_OUTPUT"
else
    run_output
fi

if [[ "$OPT_JSON" == "true" || -n "$OPT_HTML" ]]; then
    for user in "${USERS[@]}"; do
        audit_one_user "$user"
        apply_fail_on
    done
fi

exit "$FINAL_EXIT"
