#!/bin/zsh
# CLAUDE-AUDIT - Claude Code local security audit tool (macOS/Zsh)
# Read-only audit for ~/.claude configuration, MCP servers, hooks, sessions, and projects.
# Unofficial project. Not affiliated with, endorsed by, sponsored by, or maintained by Anthropic.
setopt PIPE_FAIL KSH_ARRAYS BASH_REMATCH TYPESET_SILENT NULL_GLOB

VERSION="0.2.0"
SCRIPT_NAME="${0:t}"
CLAUDE_DIR_NAME=".claude"
DANGEROUS_MCP_HINTS="bash sh zsh python python3 node ruby perl osascript sqlite3 psql mysql curl wget nc ncat ssh scp"
SENSITIVE_NAME_RE='(token|secret|password|passwd|api[_-]?key|credential|auth|session|cookie)'
HAS_JQ=false

# Field separator for packed inventory rows. ASCII Unit Separator is used instead
# of "|" because hook and monitor commands routinely contain pipes
# (e.g. "curl ... | bash"), which would otherwise split a row into wrong fields.
FS=$'\x1f'

# Managed (enterprise policy) settings locations - macOS
MANAGED_SETTINGS_FILE="/Library/Application Support/ClaudeCode/managed-settings.json"
MANAGED_SETTINGS_DIR="/Library/Application Support/ClaudeCode/managed-settings.d"
MANAGED_PREF_DOMAIN="com.anthropic.claudecode"

# Hook events known to Claude Code 2.1.x. Unknown names are reported as INFO so the
# tool degrades gracefully when Anthropic adds new events.
KNOWN_HOOK_EVENTS="SessionStart Setup UserPromptSubmit UserPromptExpansion PreToolUse PermissionRequest PermissionDenied PostToolUse PostToolUseFailure PostToolBatch Notification MessageDisplay SubagentStart SubagentStop TaskCreated TaskCompleted Stop StopFailure TeammateIdle InstructionsLoaded ConfigChange CwdChanged DirectoryAdded FileChanged WorktreeCreate WorktreeRemove PreCompact PostCompact Elicitation ElicitationResult SessionEnd"

# Marketplaces published by Anthropic; anything else is third-party code.
OFFICIAL_MARKETPLACES="claude-plugins-official claude-community anthropics/claude-plugins-official anthropics/claude-plugins-community inline"

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
PLUGINS=()
SKILLS=()
MONITORS=()
SECURITY_SETTINGS=()

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
    # Packed rows reach the renderers verbatim; show the separator as a pipe.
    s="${s//${FS}/ | }"
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

# Risk tags for a hook. Handles every hook type supported by Claude Code 2.1.x:
# command, http, mcp_tool, prompt, agent.
hook_risk_tags() {
    local cmd="$1" htype="${2:-command}" headers="${3:-}" async="${4:-false}" tags=() lower
    lower="${(L)cmd}"

    case "$htype" in
        http)
            tags+=("http-endpoint")
            # A hook posting session data off-box is materially different from a local one.
            [[ "$lower" == http://localhost* || "$lower" == http://127.0.0.1* || "$lower" == https://localhost* ]] \
                || tags+=("remote-endpoint")
            [[ "$lower" == http://* ]] && tags+=("cleartext-http")
            [[ -n "$headers" && "${(L)headers}" =~ '(authorization|token|api[_-]?key|secret|cookie)' ]] && tags+=("credential-header")
            ;;
        mcp_tool) tags+=("mcp-tool-invocation") ;;
        prompt|agent) tags+=("model-invocation") ;;
    esac

    if [[ "$htype" == "command" ]]; then
        [[ "$lower" == *"curl"* || "$lower" == *"wget"* || "$lower" == *"http"* || "$lower" == *"nc "* ]] && tags+=("network")
        [[ "$lower" == *"rm "* || "$lower" == *"delete"* || "$lower" == *"truncate"* ]] && tags+=("destructive")
        [[ "$lower" == *"git push"* || "$lower" == *"git commit"* ]] && tags+=("git-write")
        [[ "$lower" == *"osascript"* || "$lower" == *"open -a"* ]] && tags+=("gui-or-applescript")
        [[ "$lower" == *"sudo"* ]] && tags+=("elevated-privilege")
        [[ "$lower" == *"eval"* || "$lower" == *"base64 -d"* || "$lower" == *"| sh"* || "$lower" == *"| bash"* ]] && tags+=("dynamic-code-execution")
    fi

    [[ "$async" == "true" ]] && tags+=("async-background")
    local IFS=","
    printf '%s' "${tags[*]}"
}

# Record a security-relevant setting so it lands in the report inventory.
# add_security_setting <key> <value> <source> <severity|""> [message]
add_security_setting() {
    local key="$1" val="$2" src="$3" sev="${4:-}" msg="${5:-}"
    SECURITY_SETTINGS+=("$key${FS}$val${FS}$src")
    [[ -n "$sev" ]] && add_finding "$sev" "Settings" "${msg:-$key = $val}" "source=$src; $key=$val"
}

# Permission lists routinely run to thousands of characters. Keep the count,
# which is what matters, and only a readable preview of the entries.
summarize_list() {
    local text="$1" count="$2" max=360
    [[ -z "$text" ]] && return 0
    if (( ${#text} > max )); then
        printf '%s entries: %s ...(truncated)' "$count" "${text:0:$max}"
    else
        printf '%s entries: %s' "$count" "$text"
    fi
}

# Read a scalar from a JSON file; prints nothing when absent/null/empty.
json_scalar() {
    local file="$1" filter="$2" out
    out=$(jq -r "$filter // empty" "$file" 2>/dev/null)
    [[ "$out" == "null" ]] && out=""
    printf '%s' "$out"
}

# Parse name/description from a SKILL.md (or agent .md) YAML frontmatter block.
parse_skill_frontmatter() {
    local file="$1" name="" desc="" tools="" model="" line in_desc=false first
    [[ -r "$file" ]] || { printf '%s|%s|%s|%s' "$(basename "${file:h}")" "" "" ""; return 0; }
    first=$(sed -n '1p' "$file" 2>/dev/null)
    if [[ "$first" != "---"* ]]; then
        printf '%s%s%s%s' "$(basename "${file:h}")" "$FS" "$FS" "$FS"
        return 0
    fi
    while IFS= read -r line; do
        [[ "$line" == "---" && -n "$name$desc$tools$model" ]] && break
        if [[ "$line" == name:* ]]; then
            name=$(strip_quotes "${line#name:}"); in_desc=false
        elif [[ "$line" == description:* ]]; then
            desc=$(strip_quotes "${line#description:}")
            [[ "$desc" == ">" || "$desc" == "|" ]] && desc=""
            in_desc=true
        elif [[ "$line" == allowed-tools:* || "$line" == tools:* ]]; then
            tools=$(strip_quotes "${line#*:}"); in_desc=false
        elif [[ "$line" == model:* ]]; then
            model=$(strip_quotes "${line#model:}"); in_desc=false
        elif [[ "$in_desc" == "true" && "$line" == "  "* ]]; then
            desc="${desc}${desc:+ }${line#  }"
        elif [[ "$line" != "---" ]]; then
            in_desc=false
        fi
    done < "$file"
    [[ -z "$name" ]] && name="$(basename "${file:h}")"
    # Keep descriptions short: they are inventory labels, not documentation.
    printf '%s%s%s%s%s%s%s' "$name" "$FS" "${desc:0:200}" "$FS" "$tools" "$FS" "$model"
}

# Classify a plugin marketplace as Anthropic-published or third-party.
plugin_provenance() {
    local marketplace="$1" hint
    for hint in ${(z)OFFICIAL_MARKETPLACES}; do
        [[ "$marketplace" == "$hint" ]] && { printf 'anthropic-published'; return 0; }
    done
    [[ "$marketplace" == "skills-dir" ]] && { printf 'local-skills-dir'; return 0; }
    [[ -z "$marketplace" ]] && { printf 'unknown'; return 0; }
    printf 'third-party'
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
    PLUGINS=()
    SKILLS=()
    MONITORS=()
    SECURITY_SETTINGS=()
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

# Extract every hook from a settings file or a plugin hooks.json, covering all
# hook types (command, http, mcp_tool, prompt, agent) and matcher groups.
parse_hooks_from_json() {
    local file="$1" label="$2"
    [[ -r "$file" ]] || return 0
    [[ "$HAS_JQ" != "true" ]] && return 0

    local rows event matcher htype descriptor async once headers timeout risk known hint
    rows=$(jq -r '
        def htype($h): if ($h|type) == "string" then "command" else ($h.type // "command") end;
        def descr($h):
            if ($h|type) == "string" then $h
            elif ($h.command // null) != null then
                (($h.command|tostring) +
                 (if ($h.args // null) != null then " " + (($h.args|map(tostring))|join(" ")) else "" end))
            elif ($h.url // null) != null then ($h.url|tostring)
            elif ($h.server // null) != null then (($h.server|tostring) + ":" + (($h.tool // "?")|tostring))
            elif ($h.prompt // null) != null then ($h.prompt|tostring|.[0:160])
            else "(unspecified)" end;
        (.hooks // {}) | to_entries[]
        | .key as $event
        | ((.value | if type == "array" then . else [.] end)[]) as $entry
        | ( if ($entry|type) == "object" and (($entry.hooks? // null) != null)
            then (($entry.hooks | if type == "array" then . else [.] end)[]) as $h
                 | [$event, ($entry.matcher // "*"), $h]
            else [$event, "*", $entry] end )
        | . as [$ev, $m, $h]
        | [ $ev, ($m|tostring), htype($h), descr($h),
            ((if ($h|type) == "object" then ($h.async // false) else false end)|tostring),
            ((if ($h|type) == "object" then ($h.once // false) else false end)|tostring),
            (if ($h|type) == "object" then (($h.headers // {})|keys|join(",")) else "" end),
            ((if ($h|type) == "object" then ($h.timeout // "") else "" end)|tostring)
          ] | @tsv
    ' "$file" 2>/dev/null) || return 0

    [[ -z "$rows" ]] && return 0
    while IFS=$'\t' read -r event matcher htype descriptor async once headers timeout; do
        [[ -n "$event" ]] || continue
        risk="$(hook_risk_tags "$descriptor" "$htype" "$headers" "$async")"
        HOOKS+=("$event${FS}$label${FS}$htype${FS}$matcher${FS}$descriptor${FS}$risk")
        add_finding "REVIEW" "Hooks" "Hook configured: $event ($htype)" \
            "source=$label; matcher=$matcher; target=${descriptor:0:90}${risk:+; risk=$risk}"
        [[ -n "$risk" ]] && add_finding "WARN" "Hooks" "Hook has elevated risk: $event ($htype)" \
            "risk=$risk; target=${descriptor:0:90}"

        known=false
        for hint in ${(z)KNOWN_HOOK_EVENTS}; do
            [[ "$event" == "$hint" ]] && { known=true; break; }
        done
        [[ "$known" == "false" ]] && add_finding "INFO" "Hooks" "Unrecognized hook event name: $event" \
            "source=$label; not in the known event list for Claude Code 2.1.x"
    done <<< "$rows"
}

collect_config() {
    local cfg="$HOME_DIR/.claude.json"
    if [[ ! -f "$cfg" ]]; then
        add_finding "INFO" "Config" ".claude.json not found" "$cfg"
        return 0
    fi

    local mode
    mode=$(file_mode "$cfg")
    SENSITIVE_FILES+=(".claude.json${FS}$mode${FS}$cfg")
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
        local enabled_mcp disabled_mcp local_mcp ext_includes ctx_uris
        enabled_mcp=$(jq -r --arg p "$proj" '(.projects[$p].enabledMcpjsonServers // []) | join(", ")' "$cfg" 2>/dev/null)
        disabled_mcp=$(jq -r --arg p "$proj" '(.projects[$p].disabledMcpjsonServers // []) | join(", ")' "$cfg" 2>/dev/null)
        local_mcp=$(jq -r --arg p "$proj" '(.projects[$p].mcpServers // {}) | keys | join(", ")' "$cfg" 2>/dev/null)
        ext_includes=$(jq -r --arg p "$proj" '.projects[$p].hasClaudeMdExternalIncludesApproved // false' "$cfg" 2>/dev/null)
        ctx_uris=$(jq -r --arg p "$proj" '(.projects[$p].mcpContextUris // []) | join(", ")' "$cfg" 2>/dev/null)
        PROJECTS+=("$proj${FS}trust=$trust_accepted${FS}tools=${allowed_tools:-none}${FS}mcp_enabled=${enabled_mcp:-none}${FS}mcp_disabled=${disabled_mcp:-none}${FS}mcp_local=${local_mcp:-none}${FS}external_includes=$ext_includes")
        if [[ "$trust_accepted" == "true" ]]; then
            add_finding "WARN" "Projects" "Trusted project grants Claude Code broader workspace autonomy" "$proj"
        fi
        # Locally-scoped MCP servers live in .claude.json rather than .mcp.json.
        if [[ -n "$local_mcp" ]]; then
            add_finding "REVIEW" "MCP Servers" "Project-local MCP servers defined in .claude.json: $(basename "$proj")" "$local_mcp"
            local lm cmd_lm
            while IFS= read -r lm; do
                [[ -n "$lm" ]] || continue
                cmd_lm=$(jq -r --arg p "$proj" --arg n "$lm" '.projects[$p].mcpServers[$n].command // .projects[$p].mcpServers[$n].url // ""' "$cfg" 2>/dev/null)
                local tagged="${lm}(project-local:$(basename "$proj"))"
                if [[ " ${MCP_NAMES[*]} " != *" $tagged "* ]]; then
                    MCP_NAMES+=("$tagged")
                    MCP_CMDS[$tagged]="$(redact_value command "$cmd_lm")"
                    MCP_ARGS[$tagged]=""
                    MCP_ENVKEYS[$tagged]="$(jq -r --arg p "$proj" --arg n "$lm" '(.projects[$p].mcpServers[$n].env // {}) | keys | join(", ")' "$cfg" 2>/dev/null)"
                    MCP_TYPE[$tagged]="$(jq -r --arg p "$proj" --arg n "$lm" '.projects[$p].mcpServers[$n].type // "stdio"' "$cfg" 2>/dev/null)"
                    local base_lm
                    base_lm="$(basename "$cmd_lm" 2>/dev/null)"
                    for hint in ${(z)DANGEROUS_MCP_HINTS}; do
                        [[ "$base_lm" == "$hint" ]] && add_finding "WARN" "MCP Servers" "MCP server uses command-capable runtime: $lm" "$cmd_lm"
                    done
                fi
            done <<< "$(jq -r --arg p "$proj" '(.projects[$p].mcpServers // {}) | keys[]' "$cfg" 2>/dev/null)"
        fi
        # External includes in CLAUDE.md pull instructions from outside the repo.
        [[ "$ext_includes" == "true" ]] && add_finding "REVIEW" "Projects" \
            "CLAUDE.md external includes approved for $(basename "$proj")" \
            "instructions may be loaded from outside the workspace"
        [[ -n "$ctx_uris" ]] && add_finding "INFO" "Projects" "MCP context URIs configured: $(basename "$proj")" "$ctx_uris"
        if [[ -n "$allowed_tools" ]]; then
            local n_proj_tools
            n_proj_tools=$(jq -r --arg p "$proj" '(.projects[$p].allowedTools // []) | length' "$cfg" 2>/dev/null)
            add_finding "REVIEW" "Projects" "Project has pre-approved tools: $(basename "$proj")" \
                "$(summarize_list "$allowed_tools" "$n_proj_tools")"
            ALLOWED_TOOLS+=("$proj${FS}$allowed_tools")
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

    # Plugin / skill usage history
    local plugin_count skill_count plugin_names
    plugin_count=$(jq -r '(.pluginUsage // {}) | length' "$cfg" 2>/dev/null)
    skill_count=$(jq -r '(.skillUsage // {}) | length' "$cfg" 2>/dev/null)
    if ((plugin_count > 0)); then
        plugin_names=$(jq -r '(.pluginUsage // {}) | keys | join(", ")' "$cfg" 2>/dev/null)
        add_finding "INFO" "Plugins" "$plugin_count plugin package(s) in usage history" "$plugin_names"
        local pu
        while IFS= read -r pu; do
            [[ -n "$pu" ]] || continue
            local pu_mkt="${pu##*@}" pu_prov
            [[ "$pu_mkt" == "$pu" ]] && pu_mkt=""
            pu_prov="$(plugin_provenance "$pu_mkt")"
            if [[ " ${PLUGINS[*]} " != *"$pu${FS}"* ]]; then
                PLUGINS+=("$pu${FS}used${FS}usage-history${FS}$pu_prov${FS}(history only)${FS}unknown${FS}unknown${FS}")
            fi
        done <<< "$(jq -r '(.pluginUsage // {}) | keys[]' "$cfg" 2>/dev/null)"
    fi
    ((skill_count > 0)) && add_finding "INFO" "Skills" "$skill_count skill(s) in usage history" \
        "$(jq -r '(.skillUsage // {}) | keys | join(", ")' "$cfg" 2>/dev/null)"

    # Account / device identity
    local org_name seat_tier billing email machine_id
    org_name="$(json_scalar "$cfg" '.oauthAccount.organizationName')"
    seat_tier="$(json_scalar "$cfg" '.oauthAccount.seatTier')"
    billing="$(json_scalar "$cfg" '.oauthAccount.billingType')"
    email="$(json_scalar "$cfg" '.oauthAccount.emailAddress')"
    machine_id="$(json_scalar "$cfg" '.machineID')"
    # Personal orgs are named after the account email; mask it like the address itself.
    if [[ -n "$org_name" ]]; then
        local org_display="$org_name"
        [[ "$org_display" == *@*.* ]] && org_display="[personal organization]"
        add_finding "INFO" "Account" "Signed in to organization: $org_display" \
            "seat=${seat_tier:-unknown}; billing=${billing:-unknown}"
    fi
    # Report only the domain: reports are shared, the mailbox is not needed.
    [[ -n "$email" ]] && add_finding "INFO" "Account" "Account email present" "domain=${email##*@}"
    [[ -n "$machine_id" ]] && add_finding "INFO" "Account" "Machine ID present" "${machine_id:0:16}..."
}

collect_settings() {
    # Global Claude Code settings: ~/.claude/settings.json
    local gsettings="$CLAUDE_DIR/settings.json"
    if [[ -f "$gsettings" ]]; then
        local mode
        mode=$(file_mode "$gsettings")
        SENSITIVE_FILES+=("settings.json (global)${FS}$mode${FS}$gsettings")
        [[ -n "$mode" && "$mode" != "600" && "$mode" != "400" ]] && add_finding "REVIEW" "Config" "Global settings.json is readable beyond the owner" "mode=$mode"
        collect_settings_from_file "$gsettings" "global"
    fi

    # Local settings: ~/.claude/settings.local.json
    local lsettings="$CLAUDE_DIR/settings.local.json"
    if [[ -f "$lsettings" ]]; then
        local mode
        mode=$(file_mode "$lsettings")
        SENSITIVE_FILES+=("settings.local.json${FS}$mode${FS}$lsettings")
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
    parse_hooks_from_json "$file" "$label"

    # ---- Permissions -------------------------------------------------------
    local allowed_tools ask_tools banned_tools default_mode extra_dirs disable_auto
    allowed_tools=$(jq -r '(.permissions.allow // []) | join(", ")' "$file" 2>/dev/null)
    ask_tools=$(jq -r '(.permissions.ask // []) | join(", ")' "$file" 2>/dev/null)
    banned_tools=$(jq -r '(.permissions.deny // []) | join(", ")' "$file" 2>/dev/null)
    default_mode="$(json_scalar "$file" '.permissions.defaultMode')"
    extra_dirs=$(jq -r '(.permissions.additionalDirectories // []) | join(", ")' "$file" 2>/dev/null)
    disable_auto="$(json_scalar "$file" '.permissions.disableAutoMode')"

    local n_allow n_ask n_deny
    n_allow=$(jq -r '(.permissions.allow // []) | length' "$file" 2>/dev/null)
    n_ask=$(jq -r '(.permissions.ask // []) | length' "$file" 2>/dev/null)
    n_deny=$(jq -r '(.permissions.deny // []) | length' "$file" 2>/dev/null)
    [[ -n "$allowed_tools" ]] && add_finding "REVIEW" "Permissions" "Pre-approved tools in settings ($label)" \
        "$(summarize_list "$allowed_tools" "$n_allow")"
    [[ -n "$ask_tools" ]] && add_finding "INFO" "Permissions" "Tools requiring confirmation ($label)" \
        "$(summarize_list "$ask_tools" "$n_ask")"
    [[ -n "$banned_tools" ]] && add_finding "INFO" "Permissions" "Denied tools in settings ($label)" \
        "$(summarize_list "$banned_tools" "$n_deny")"
    if [[ -n "$default_mode" ]]; then
        case "$default_mode" in
            auto) add_security_setting "permissions.defaultMode" "$default_mode" "$label" "WARN" \
                    "Default permission mode is 'auto' (actions auto-approved without prompting)" ;;
            *)    add_security_setting "permissions.defaultMode" "$default_mode" "$label" "INFO" \
                    "Default permission mode: $default_mode" ;;
        esac
    fi
    if [[ -n "$extra_dirs" ]]; then
        add_security_setting "permissions.additionalDirectories" "$extra_dirs" "$label" "WARN" \
            "Additional directories are trusted beyond the workspace"
    fi
    [[ -n "$disable_auto" ]] && add_security_setting "permissions.disableAutoMode" "$disable_auto" "$label" "INFO" \
        "Auto mode is disabled by policy"

    # ---- Credential-producing helpers (these execute external commands) -----
    local key_helper aws_export aws_refresh
    key_helper="$(json_scalar "$file" '.apiKeyHelper')"
    aws_export="$(json_scalar "$file" '.awsCredentialExport')"
    aws_refresh="$(json_scalar "$file" '.awsAuthRefresh')"
    [[ -n "$key_helper" ]] && add_security_setting "apiKeyHelper" "$key_helper" "$label" "WARN" \
        "apiKeyHelper runs an external command to mint API credentials"
    [[ -n "$aws_export" ]] && add_security_setting "awsCredentialExport" "$aws_export" "$label" "WARN" \
        "awsCredentialExport runs an external script that outputs AWS credentials"
    [[ -n "$aws_refresh" ]] && add_security_setting "awsAuthRefresh" "$aws_refresh" "$label" "WARN" \
        "awsAuthRefresh runs an external script that modifies the .aws directory"

    # ---- Injected environment variables ------------------------------------
    local env_keys
    env_keys=$(jq -r '(.env // {}) | keys | join(", ")' "$file" 2>/dev/null)
    if [[ -n "$env_keys" ]]; then
        # Key names only - values may hold secrets and are never read.
        SECURITY_SETTINGS+=("env${FS}$env_keys${FS}$label")
        if [[ "${(L)env_keys}" =~ "$SENSITIVE_NAME_RE" ]]; then
            add_finding "WARN" "Settings" "Injected env vars include secret-like names ($label)" "keys=$env_keys"
        else
            add_finding "REVIEW" "Settings" "Environment variables are injected into every session ($label)" "keys=$env_keys"
        fi
    fi

    # ---- Sandbox isolation --------------------------------------------------
    local fs_disabled net_disabled cred_rules
    fs_disabled="$(json_scalar "$file" '.sandbox.filesystem.disabled')"
    net_disabled="$(json_scalar "$file" '.sandbox.network.disabled')"
    cred_rules=$(jq -r '(.sandbox.credentials // []) | length' "$file" 2>/dev/null)
    [[ "$fs_disabled" == "true" ]] && add_security_setting "sandbox.filesystem.disabled" "true" "$label" "WARN" \
        "Sandbox filesystem isolation is DISABLED"
    [[ "$net_disabled" == "true" ]] && add_security_setting "sandbox.network.disabled" "true" "$label" "WARN" \
        "Sandbox network isolation is DISABLED"
    [[ -n "$cred_rules" && "$cred_rules" != "0" ]] && add_security_setting "sandbox.credentials" "$cred_rules rule(s)" "$label" "INFO" \
        "Sandbox credential masking rules configured: $cred_rules"

    # ---- Hook controls ------------------------------------------------------
    local disable_hooks http_allow http_env
    disable_hooks="$(json_scalar "$file" '.disableAllHooks')"
    http_allow=$(jq -r '(.allowedHttpHookUrls // []) | join(", ")' "$file" 2>/dev/null)
    http_env=$(jq -r '(.httpHookAllowedEnvVars // []) | join(", ")' "$file" 2>/dev/null)
    [[ "$disable_hooks" == "true" ]] && add_security_setting "disableAllHooks" "true" "$label" "INFO" \
        "All hooks and custom status lines are disabled"
    [[ -n "$http_allow" ]] && add_security_setting "allowedHttpHookUrls" "$http_allow" "$label" "INFO" \
        "HTTP hook URL allowlist is configured"
    [[ -n "$http_env" ]] && add_security_setting "httpHookAllowedEnvVars" "$http_env" "$label" "INFO" \
        "HTTP hook header env-var allowlist is configured"

    # ---- Status line (executes a command each render) -----------------------
    local status_cmd
    status_cmd=$(jq -r '(.statusLine // empty) | if type == "object" then (.command // "") else tostring end' "$file" 2>/dev/null)
    [[ -n "$status_cmd" && "$status_cmd" != "null" ]] && add_security_setting "statusLine" "$status_cmd" "$label" "REVIEW" \
        "Custom status line executes a command"

    # ---- Plugins and marketplaces ------------------------------------------
    local enabled_plugins plugin_row pname pstate extra_mkt strict_mkt blocked_mkt no_sideload no_cmd_plugins
    enabled_plugins=$(jq -r '(.enabledPlugins // {}) | to_entries[] | "\(.key)\t\(.value)"' "$file" 2>/dev/null)
    if [[ -n "$enabled_plugins" ]]; then
        while IFS=$'\t' read -r pname pstate; do
            [[ -n "$pname" ]] || continue
            local mkt="${pname##*@}"
            [[ "$mkt" == "$pname" ]] && mkt=""
            local prov
            prov="$(plugin_provenance "$mkt")"
            PLUGINS+=("$pname${FS}$pstate${FS}$label${FS}$prov${FS}(declared in settings)${FS}unknown${FS}unknown${FS}")
            if [[ "$pstate" == "true" ]]; then
                if [[ "$prov" == "third-party" || "$prov" == "unknown" ]]; then
                    add_finding "WARN" "Plugins" "Enabled plugin from a non-Anthropic marketplace: $pname" \
                        "source=$label; provenance=$prov"
                else
                    add_finding "REVIEW" "Plugins" "Enabled plugin: $pname" "source=$label; provenance=$prov"
                fi
            fi
        done <<< "$enabled_plugins"
    fi

    extra_mkt=$(jq -r '(.extraKnownMarketplaces // {}) | if type == "object" then (keys | join(", ")) else (. | join(", ")) end' "$file" 2>/dev/null)
    strict_mkt="$(json_scalar "$file" '.strictKnownMarketplaces')"
    blocked_mkt=$(jq -r '(.blockedMarketplaces // []) | join(", ")' "$file" 2>/dev/null)
    no_sideload="$(json_scalar "$file" '.disableSideloadFlags')"
    no_cmd_plugins="$(json_scalar "$file" '.disableCommandPluginSources')"
    if [[ -n "$extra_mkt" ]]; then
        add_security_setting "extraKnownMarketplaces" "$extra_mkt" "$label" "WARN" \
            "Additional (non-Anthropic) plugin marketplaces are trusted"
    fi
    [[ "$strict_mkt" == "true" ]] && add_security_setting "strictKnownMarketplaces" "true" "$label" "INFO" \
        "Plugin installs are restricted to known marketplaces"
    [[ -n "$blocked_mkt" ]] && add_security_setting "blockedMarketplaces" "$blocked_mkt" "$label" "INFO" \
        "Blocked plugin marketplaces are configured"
    [[ "$no_sideload" == "true" ]] && add_security_setting "disableSideloadFlags" "true" "$label" "INFO" \
        "Plugin/MCP sideload CLI flags are rejected"
    [[ "$no_cmd_plugins" == "true" ]] && add_security_setting "disableCommandPluginSources" "true" "$label" "INFO" \
        "Command-sourced plugins are blocked"

    # ---- MCP governance -----------------------------------------------------
    local mcp_allow mcp_deny mcp_disabled no_connectors all_connectors managed_mcp_only
    mcp_allow=$(jq -r '(.allowedMcpServers // []) | if type == "array" then map(if type == "object" then (.serverName // tostring) else tostring end) | join(", ") else tostring end' "$file" 2>/dev/null)
    mcp_deny=$(jq -r '(.deniedMcpServers // []) | if type == "array" then map(if type == "object" then (.serverName // tostring) else tostring end) | join(", ") else tostring end' "$file" 2>/dev/null)
    mcp_disabled=$(jq -r '(.disabledMcpjsonServers // []) | join(", ")' "$file" 2>/dev/null)
    no_connectors="$(json_scalar "$file" '.disableClaudeAiConnectors')"
    all_connectors="$(json_scalar "$file" '.allowAllClaudeAiMcps')"
    managed_mcp_only="$(json_scalar "$file" '.allowManagedMcpServersOnly')"
    [[ -n "$mcp_allow" ]] && add_security_setting "allowedMcpServers" "$mcp_allow" "$label" "INFO" "MCP server allowlist: $mcp_allow"
    [[ -n "$mcp_deny" ]] && add_security_setting "deniedMcpServers" "$mcp_deny" "$label" "INFO" "MCP server denylist: $mcp_deny"
    [[ -n "$mcp_disabled" ]] && add_security_setting "disabledMcpjsonServers" "$mcp_disabled" "$label" "INFO" "Rejected .mcp.json servers: $mcp_disabled"
    [[ "$no_connectors" == "true" ]] && add_security_setting "disableClaudeAiConnectors" "true" "$label" "INFO" "claude.ai MCP connectors are disabled"
    [[ "$all_connectors" == "true" ]] && add_security_setting "allowAllClaudeAiMcps" "true" "$label" "REVIEW" "All claude.ai connectors load alongside managed MCP config"
    [[ "$managed_mcp_only" == "true" ]] && add_security_setting "allowManagedMcpServersOnly" "true" "$label" "INFO" "Only managed MCP servers are respected"

    # ---- Managed-only hardening switches ------------------------------------
    local managed_hooks_only managed_perms_only force_org min_ver max_ver managed_md
    managed_hooks_only="$(json_scalar "$file" '.allowManagedHooksOnly')"
    managed_perms_only="$(json_scalar "$file" '.allowManagedPermissionRulesOnly')"
    force_org="$(json_scalar "$file" '.forceLoginOrgUUID')"
    min_ver="$(json_scalar "$file" '.requiredMinimumVersion')"
    max_ver="$(json_scalar "$file" '.requiredMaximumVersion')"
    managed_md="$(json_scalar "$file" '.claudeMd')"
    [[ "$managed_hooks_only" == "true" ]] && add_security_setting "allowManagedHooksOnly" "true" "$label" "INFO" "Only managed hooks may run"
    [[ "$managed_perms_only" == "true" ]] && add_security_setting "allowManagedPermissionRulesOnly" "true" "$label" "INFO" "Only managed permission rules apply"
    [[ -n "$force_org" ]] && add_security_setting "forceLoginOrgUUID" "$force_org" "$label" "INFO" "Login is restricted to a specific organization"
    [[ -n "$min_ver" ]] && add_security_setting "requiredMinimumVersion" "$min_ver" "$label" "INFO" "Minimum required Claude Code version: $min_ver"
    [[ -n "$max_ver" ]] && add_security_setting "requiredMaximumVersion" "$max_ver" "$label" "INFO" "Maximum allowed Claude Code version: $max_ver"
    [[ -n "$managed_md" ]] && add_security_setting "claudeMd" "${managed_md:0:80}" "$label" "INFO" "Organization-managed CLAUDE.md instructions are injected"

    # ---- Remote control / cross-session surface -----------------------------
    local cross_inbound remote_disabled push_notif deep_link
    cross_inbound="$(json_scalar "$file" '.crossSessionInbound')"
    remote_disabled="$(json_scalar "$file" '.disableRemoteControl')"
    push_notif="$(json_scalar "$file" '.agentPushNotifEnabled')"
    deep_link="$(json_scalar "$file" '.disableDeepLinkRegistration')"
    if [[ "$cross_inbound" == "accept" ]]; then
        add_security_setting "crossSessionInbound" "accept" "$label" "REVIEW" "Inbound cross-session messages are accepted automatically"
    elif [[ -n "$cross_inbound" ]]; then
        add_security_setting "crossSessionInbound" "$cross_inbound" "$label" "INFO" "Cross-session inbound policy: $cross_inbound"
    fi
    [[ "$remote_disabled" == "true" ]] && add_security_setting "disableRemoteControl" "true" "$label" "INFO" "Remote Control is disabled"
    [[ "$push_notif" == "true" ]] && add_security_setting "agentPushNotifEnabled" "true" "$label" "INFO" "Proactive push notifications via Remote Control are enabled"
    [[ -n "$deep_link" ]] && add_security_setting "disableDeepLinkRegistration" "$deep_link" "$label" "INFO" "claude-cli:// deep link registration policy: $deep_link"

    # ---- Browser / simulator tool surface -----------------------------------
    local browser_ext browser_nav sim_tools
    browser_ext="$(json_scalar "$file" '.browserExternalPageTools')"
    browser_nav="$(json_scalar "$file" '.disableBrowserExternalNavigation')"
    sim_tools="$(json_scalar "$file" '.disableMobileSimulatorTools')"
    [[ -n "$browser_ext" ]] && add_security_setting "browserExternalPageTools" "$browser_ext" "$label" "INFO" "Browser external-page tools policy: $browser_ext"
    [[ "$browser_nav" == "true" ]] && add_security_setting "disableBrowserExternalNavigation" "true" "$label" "INFO" "External browsing in the Browser pane is blocked"
    [[ "$sim_tools" == "true" ]] && add_security_setting "disableMobileSimulatorTools" "true" "$label" "INFO" "iOS Simulator tools are blocked"

    # ---- Auto-mode classifier ----------------------------------------------
    local am_allow am_hard am_shell
    am_allow=$(jq -r '(.autoMode.allow // []) | join(", ")' "$file" 2>/dev/null)
    am_hard=$(jq -r '(.autoMode.hard_deny // []) | join(", ")' "$file" 2>/dev/null)
    am_shell="$(json_scalar "$file" '.autoMode.classifyAllShell')"
    [[ -n "$am_allow" ]] && add_security_setting "autoMode.allow" "$am_allow" "$label" "REVIEW" "Auto-mode allow rules are configured"
    [[ -n "$am_hard" ]] && add_security_setting "autoMode.hard_deny" "$am_hard" "$label" "INFO" "Auto-mode hard-deny rules are configured"
    [[ "$am_shell" == "true" ]] && add_security_setting "autoMode.classifyAllShell" "true" "$label" "INFO" "All shell commands are routed through the auto-mode classifier"

    # ---- Data retention / memory -------------------------------------------
    local cleanup_days auto_memory memory_dir
    cleanup_days="$(json_scalar "$file" '.cleanupPeriodDays')"
    auto_memory="$(json_scalar "$file" '.autoMemoryEnabled')"
    memory_dir="$(json_scalar "$file" '.autoMemoryDirectory')"
    if [[ -n "$cleanup_days" ]]; then
        if ((cleanup_days > 90)); then
            add_security_setting "cleanupPeriodDays" "$cleanup_days" "$label" "REVIEW" \
                "Session data is retained for $cleanup_days days (default is 30)"
        else
            add_security_setting "cleanupPeriodDays" "$cleanup_days" "$label" "INFO" "Session data retention: $cleanup_days days"
        fi
    fi
    [[ "$auto_memory" == "false" ]] && add_security_setting "autoMemoryEnabled" "false" "$label" "INFO" "Auto memory is disabled"
    [[ -n "$memory_dir" ]] && add_security_setting "autoMemoryDirectory" "$memory_dir" "$label" "INFO" "Custom auto-memory directory is configured"

    # ---- Feature toggles and model policy ----------------------------------
    local model avail_models enforce_models main_agent out_style def_shell no_bundled no_artifact no_agentview
    model="$(json_scalar "$file" '.model')"
    avail_models=$(jq -r '(.availableModels // []) | join(", ")' "$file" 2>/dev/null)
    enforce_models="$(json_scalar "$file" '.enforceAvailableModels')"
    main_agent="$(json_scalar "$file" '.agent')"
    out_style="$(json_scalar "$file" '.outputStyle')"
    def_shell="$(json_scalar "$file" '.defaultShell')"
    no_bundled="$(json_scalar "$file" '.disableBundledSkills')"
    no_artifact="$(json_scalar "$file" '.disableArtifact')"
    no_agentview="$(json_scalar "$file" '.disableAgentView')"
    [[ -n "$model" ]] && add_finding "INFO" "Config" "Model override in settings ($label): $model"
    [[ -n "$avail_models" ]] && add_security_setting "availableModels" "$avail_models" "$label" "INFO" "Model choices are restricted"
    [[ "$enforce_models" == "true" ]] && add_security_setting "enforceAvailableModels" "true" "$label" "INFO" "Model restriction is enforced"
    [[ -n "$main_agent" ]] && add_security_setting "agent" "$main_agent" "$label" "REVIEW" \
        "A custom agent runs as the main thread (overrides default system prompt and tools)"
    [[ -n "$out_style" ]] && add_security_setting "outputStyle" "$out_style" "$label" "INFO" "Output style: $out_style"
    [[ -n "$def_shell" ]] && add_security_setting "defaultShell" "$def_shell" "$label" "INFO" "Default shell: $def_shell"
    [[ "$no_bundled" == "true" ]] && add_security_setting "disableBundledSkills" "true" "$label" "INFO" "Bundled skills and workflows are disabled"
    [[ "$no_artifact" == "true" ]] && add_security_setting "disableArtifact" "true" "$label" "INFO" "Artifact publishing is disabled"
    [[ "$no_agentview" == "true" ]] && add_security_setting "disableAgentView" "true" "$label" "INFO" "Background agents and agent view are disabled"
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

# Enterprise policy settings outrank every user setting, so their presence (or
# absence) is a material fact about the machine.
collect_managed_settings() {
    local found=false f mode
    if [[ -f "$MANAGED_SETTINGS_FILE" ]]; then
        found=true
        mode=$(file_mode "$MANAGED_SETTINGS_FILE")
        SENSITIVE_FILES+=("managed-settings.json${FS}$mode${FS}$MANAGED_SETTINGS_FILE")
        add_finding "INFO" "Managed Policy" "Enterprise managed settings are in effect" "$MANAGED_SETTINGS_FILE (mode=$mode)"
        collect_settings_from_file "$MANAGED_SETTINGS_FILE" "managed"
    fi
    for f in "$MANAGED_SETTINGS_DIR"/*.json; do
        [[ -r "$f" ]] || continue
        found=true
        add_finding "INFO" "Managed Policy" "Managed settings drop-in: $(basename "$f")" "$f"
        collect_settings_from_file "$f" "managed-dropin:$(basename "$f")"
    done
    if command -v defaults >/dev/null 2>&1; then
        if defaults read "$MANAGED_PREF_DOMAIN" >/dev/null 2>&1; then
            found=true
            add_finding "INFO" "Managed Policy" "MDM managed preferences are present" "domain=$MANAGED_PREF_DOMAIN"
        fi
    fi
    [[ "$found" == "false" ]] && add_finding "INFO" "Managed Policy" "No enterprise managed settings found" \
        "unmanaged installation; user settings are authoritative"
}

# Report which auto-executing components a plugin ships. Plugins are arbitrary
# third-party code, so the component list is the interesting part.
plugin_components() {
    local root="$1" parts=()
    [[ -f "$root/hooks/hooks.json" || -f "$root/hooks.json" ]] && parts+=("hooks")
    [[ -f "$root/.mcp.json" ]] && parts+=("mcp")
    [[ -f "$root/.lsp.json" ]] && parts+=("lsp")
    [[ -f "$root/monitors/monitors.json" || -f "$root/monitors.json" ]] && parts+=("monitors")
    [[ -d "$root/bin" ]] && parts+=("bin")
    [[ -d "$root/agents" ]] && parts+=("agents")
    [[ -d "$root/skills" ]] && parts+=("skills")
    [[ -d "$root/commands" ]] && parts+=("commands")
    [[ -f "$root/settings.json" ]] && parts+=("settings")
    local IFS=","
    printf '%s' "${parts[*]}"
}

# Inspect one plugin root: manifest metadata, executable surface, nested MCP/hooks.
inspect_plugin() {
    local root="$1" marketplace="$2" scope="$3"
    local manifest="$root/.claude-plugin/plugin.json"
    local pname="" pver="" pauthor="" prov components

    if [[ -r "$manifest" && "$HAS_JQ" == "true" ]]; then
        pname="$(json_scalar "$manifest" '.name')"
        pver="$(json_scalar "$manifest" '.version')"
        pauthor=$(jq -r '(.author // "") | if type == "object" then (.name // .email // .url // "") else tostring end' "$manifest" 2>/dev/null)
    fi
    [[ -z "$pname" ]] && pname="$(basename "$root")"
    prov="$(plugin_provenance "$marketplace")"
    components="$(plugin_components "$root")"

    PLUGINS+=("${pname}@${marketplace:-unknown}${FS}installed${FS}$scope${FS}$prov${FS}${components:-none}${FS}${pver:-unknown}${FS}${pauthor:-unknown}${FS}$root")

    if [[ "$prov" == "third-party" || "$prov" == "unknown" ]]; then
        add_finding "WARN" "Plugins" "Installed plugin from a non-Anthropic source: $pname" \
            "marketplace=${marketplace:-unknown}; provenance=$prov; components=${components:-none}"
    else
        add_finding "INFO" "Plugins" "Installed plugin: $pname" \
            "marketplace=${marketplace:-unknown}; version=${pver:-unknown}; components=${components:-none}"
    fi

    # bin/ is prepended to PATH for Bash tool calls while the plugin is enabled.
    if [[ -d "$root/bin" ]]; then
        local execs
        execs=$(find "$root/bin" -maxdepth 1 -type f -perm -u+x 2>/dev/null | while read -r e; do basename "$e"; done | paste -sd ', ' -)
        add_finding "WARN" "Plugins" "Plugin adds executables to the Bash PATH: $pname" "bin=${execs:-none}"
    fi
    [[ -f "$root/.lsp.json" ]] && add_finding "REVIEW" "Plugins" "Plugin starts language server processes: $pname" "$root/.lsp.json"

    # Nested components carry their own execution surface.
    [[ -f "$root/.mcp.json" ]] && parse_mcp_servers_from_json "$root/.mcp.json" "plugin:$pname"
    [[ -f "$root/hooks/hooks.json" ]] && parse_hooks_from_json "$root/hooks/hooks.json" "plugin:$pname"
    [[ -f "$root/hooks.json" ]] && parse_hooks_from_json "$root/hooks.json" "plugin:$pname"
    collect_monitors_from "$root" "$pname"
}

# Background monitors run unsandboxed shell commands for the whole session.
collect_monitors_from() {
    local root="$1" pname="$2" mfile="" rows name cmd when desc
    [[ "$HAS_JQ" == "true" ]] || return 0
    [[ -f "$root/monitors/monitors.json" ]] && mfile="$root/monitors/monitors.json"
    [[ -z "$mfile" && -f "$root/monitors.json" ]] && mfile="$root/monitors.json"
    [[ -n "$mfile" ]] || return 0

    rows=$(jq -r '
        (if type == "array" then . else (.monitors // []) end)[]
        | [(.name // "unnamed"), (.command // ""), (.when // "always"), (.description // "")] | @tsv
    ' "$mfile" 2>/dev/null) || return 0
    [[ -z "$rows" ]] && return 0
    while IFS=$'\t' read -r name cmd when desc; do
        [[ -n "$name" ]] || continue
        MONITORS+=("$name${FS}$pname${FS}$when${FS}$cmd${FS}$desc")
        add_finding "WARN" "Monitors" "Plugin runs a background monitor command: $pname/$name" \
            "when=$when; cmd=${cmd:0:100}"
    done <<< "$rows"
}

collect_plugins() {
    local manifest plugin_root marketplace version_dir d

    # Marketplace plugins: ~/.claude/plugins/cache/{marketplace}/{plugin}/{version}/
    for manifest in "$CLAUDE_DIR"/plugins/cache/*/*/*/.claude-plugin/plugin.json; do
        [[ -r "$manifest" ]] || continue
        plugin_root="${manifest:h:h}"
        marketplace="$(basename "${plugin_root:h:h}")"
        inspect_plugin "$plugin_root" "$marketplace" "user-cache"
    done
    # Plugins without a manifest still load via auto-discovery.
    for version_dir in "$CLAUDE_DIR"/plugins/cache/*/*/*; do
        [[ -d "$version_dir" ]] || continue
        [[ -f "$version_dir/.claude-plugin/plugin.json" ]] && continue
        [[ -n "$(plugin_components "$version_dir")" ]] || continue
        marketplace="$(basename "${version_dir:h:h}")"
        inspect_plugin "$version_dir" "$marketplace" "user-cache"
    done

    # Skills-directory plugins auto-load with no marketplace or install step.
    for d in "$CLAUDE_DIR"/skills/*; do
        [[ -d "$d" ]] || continue
        [[ -f "$d/.claude-plugin/plugin.json" ]] || continue
        inspect_plugin "$d" "skills-dir" "user-skills-dir"
    done

    local data_dir="$CLAUDE_DIR/plugins/data"
    if [[ -d "$data_dir" ]]; then
        local dcount
        dcount=$(find "$data_dir" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
        ((dcount > 0)) && add_finding "INFO" "Plugins" "Persistent plugin data directories: $dcount" "$data_dir"
    fi
    ((${#PLUGINS[@]} > 0)) && add_finding "INFO" "Plugins" "${#PLUGINS[@]} plugin record(s) found"
}

# Skills, agents and commands are model-invocable instructions; inventory them so
# drift shows up in diffs.
add_skill_entry() {
    local file="$1" kind="$2" source="$3" parsed name desc tools model
    [[ -r "$file" ]] || return 0
    parsed="$(parse_skill_frontmatter "$file")"
    name="$(json_split_field "$parsed" 1)"
    desc="$(json_split_field "$parsed" 2)"
    tools="$(json_split_field "$parsed" 3)"
    model="$(json_split_field "$parsed" 4)"
    SKILLS+=("$name${FS}$kind${FS}$source${FS}$desc${FS}${tools:-default}${FS}$file")
    [[ -n "$tools" ]] && add_finding "INFO" "Skills" "$kind declares explicit tool access: $name" "tools=$tools; source=$source"
}

collect_skills() {
    local f d proj proj_paths

    for f in "$CLAUDE_DIR"/skills/*/SKILL.md "$CLAUDE_DIR"/skills/*/skills/*/SKILL.md; do
        [[ -r "$f" ]] && add_skill_entry "$f" "skill" "user"
    done
    for f in "$CLAUDE_DIR"/plugins/cache/*/*/*/skills/*/SKILL.md "$CLAUDE_DIR"/plugins/cache/*/*/*/SKILL.md; do
        [[ -r "$f" ]] && add_skill_entry "$f" "skill" "plugin"
    done
    for f in "$CLAUDE_DIR"/agents/*.md "$CLAUDE_DIR"/plugins/cache/*/*/*/agents/*.md; do
        [[ -r "$f" ]] && add_skill_entry "$f" "agent" "user"
    done
    for f in "$CLAUDE_DIR"/commands/**/*.md; do
        [[ -r "$f" ]] && add_skill_entry "$f" "command" "user"
    done

    # Project scope loads only after the workspace trust dialog is accepted.
    if [[ "$HAS_JQ" == "true" && -f "$HOME_DIR/.claude.json" ]]; then
        proj_paths=$(jq -r '(.projects // {}) | keys[]' "$HOME_DIR/.claude.json" 2>/dev/null)
        while IFS= read -r proj; do
            [[ -n "$proj" && -d "$proj" ]] || continue
            for f in "$proj"/.claude/skills/*/SKILL.md; do
                [[ -r "$f" ]] && add_skill_entry "$f" "skill" "project:$(basename "$proj")"
            done
            for f in "$proj"/.claude/agents/*.md; do
                [[ -r "$f" ]] && add_skill_entry "$f" "agent" "project:$(basename "$proj")"
            done
            for d in "$proj"/.claude/skills/*; do
                [[ -d "$d" && -f "$d/.claude-plugin/plugin.json" ]] || continue
                inspect_plugin "$d" "skills-dir" "project:$(basename "$proj")"
            done
        done <<< "$proj_paths"
    fi
    ((${#SKILLS[@]} > 0)) && add_finding "INFO" "Skills" "${#SKILLS[@]} skill/agent/command definition(s) found"
}

collect_desktop_config() {
    local app_support="$HOME_DIR/Library/Application Support/Claude"
    local desktop_cfg="$app_support/claude_desktop_config.json"
    [[ -f "$desktop_cfg" ]] || return 0

    local mode
    mode=$(file_mode "$desktop_cfg")
    SENSITIVE_FILES+=("claude_desktop_config.json${FS}$mode${FS}$desktop_cfg")

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
        SENSITIVE_FILES+=("$fname${FS}$mode${FS}$p")
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
        SENSITIVE_FILES+=("ant-did${FS}$mode${FS}$ant_did")
        add_finding "INFO" "Sensitive Files" "ant-did (device identity) present" "mode=$mode"
    fi

    # Session peer tokens: ~/.claude/sessions/<pid>.<hash>.key holds a live
    # credential used to attach to a running session.
    local kf key_count=0
    for kf in "$CLAUDE_DIR"/sessions/*.key; do
        [[ -f "$kf" ]] || continue
        ((key_count++))
        mode=$(file_mode "$kf")
        SENSITIVE_FILES+=("sessions/$(basename "$kf")${FS}$mode${FS}$kf")
        if [[ "$mode" != "600" && "$mode" != "400" ]]; then
            add_finding "WARN" "Sensitive Files" "Session peer-token key is readable beyond the owner" \
                "mode=$mode; $(basename "$kf")"
        fi
    done
    ((key_count > 0)) && add_finding "INFO" "Sensitive Files" "$key_count session peer-token key file(s) present" \
        "$CLAUDE_DIR/sessions"

    # OAuth credentials: a file on Linux/WSL, the login keychain on macOS.
    local cred_file="$CLAUDE_DIR/.credentials.json"
    if [[ -f "$cred_file" ]]; then
        mode=$(file_mode "$cred_file")
        SENSITIVE_FILES+=(".credentials.json${FS}$mode${FS}$cred_file")
        if [[ "$mode" != "600" && "$mode" != "400" ]]; then
            add_finding "WARN" "Sensitive Files" "OAuth credentials file is readable beyond the owner" "mode=$mode"
        else
            add_finding "REVIEW" "Sensitive Files" "OAuth credentials file present" "mode=$mode"
        fi
    elif [[ "$AUDIT_USER" == "$(id -un)" ]] && command -v security >/dev/null 2>&1; then
        if security find-generic-password -s "Claude Code-credentials" >/dev/null 2>&1; then
            add_finding "INFO" "Sensitive Files" "OAuth credentials stored in the login keychain" \
                "service=Claude Code-credentials (value not read)"
        fi
    fi

    # Telemetry spool: undelivered events queued on disk.
    local tel_dir="$CLAUDE_DIR/telemetry"
    if [[ -d "$tel_dir" ]]; then
        local tel_count tel_bytes
        tel_count="$(dir_file_count "$tel_dir")"
        tel_bytes="$(dir_total_bytes "$tel_dir")"
        ((tel_count > 0)) && add_finding "REVIEW" "Local Data" "Undelivered telemetry events are spooled on disk" \
            "$tel_count file(s); size=$(fmt_bytes "$tel_bytes"); $tel_dir"
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
    for name in sessions shell-snapshots session-env projects tasks telemetry todos history file-history plugins/cache plugins/data; do
        dir="$CLAUDE_DIR/$name"
        [[ -d "$dir" ]] || continue
        count="$(dir_file_count "$dir")"
        bytes="$(dir_total_bytes "$dir")"
        latest="$(dir_latest_mtime "$dir")"
        RETENTION_ITEMS+=("$name${FS}$count${FS}$bytes${FS}$latest${FS}$dir")
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
        RETENTION_ITEMS+=("cowork-user-files${FS}$count${FS}$bytes${FS}$latest${FS}$cowork_path")
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
        RETENTION_ITEMS+=("$name${FS}$count${FS}$bytes${FS}$latest${FS}$dir")
        add_finding "INFO" "Retention" "$name contains $count file(s)" "size=$(fmt_bytes "$bytes"); latest=${latest:-none}"
    done
}

collect_runtime() {
    local out count line la_dir plist crons

    # Installed version: the audit rules track a specific Claude Code generation,
    # so record which one this machine is actually running.
    local app_support="$HOME_DIR/Library/Application Support/Claude"
    local vdir versions=()
    for vdir in "$app_support"/claude-code/*; do
        [[ -d "$vdir" ]] || continue
        versions+=("$(basename "$vdir")")
    done
    if ((${#versions[@]} > 0)); then
        add_finding "INFO" "Runtime" "Claude Code version(s) installed: ${(j:, :)versions}" "$app_support/claude-code"
    elif command -v claude >/dev/null 2>&1; then
        add_finding "INFO" "Runtime" "Claude Code version: $(claude --version 2>/dev/null | head -1)"
    fi

    # Background task records written by the Task/agent system.
    local tasks_dir="$CLAUDE_DIR/tasks"
    if [[ -d "$tasks_dir" ]]; then
        local task_count
        task_count=$(find "$tasks_dir" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
        ((task_count > 0)) && add_finding "INFO" "Runtime" "Background task record(s) on disk: $task_count" "$tasks_dir"
    fi

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
                ACTIVE_SESSIONS+=("${sess_pid:-?}${FS}${sess_kind:-unknown}${FS}${sess_ver:-?}${FS}${sess_cwd:-?}")
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

# Checks that only make sense once every source has been parsed.
finalize_cross_checks() {
    local row http_hooks=0 has_allowlist=false

    for row in "${HOOKS[@]}"; do
        [[ "$(json_split_field "$row" 3)" == "http" ]] && ((http_hooks++))
    done
    for row in "${SECURITY_SETTINGS[@]}"; do
        [[ "${row%%${FS}*}" == "allowedHttpHookUrls" ]] && has_allowlist=true
    done
    if ((http_hooks > 0)) && [[ "$has_allowlist" == "false" ]]; then
        add_finding "WARN" "Hooks" "HTTP hooks are configured with no URL allowlist" \
            "$http_hooks HTTP hook(s); set allowedHttpHookUrls to restrict where session data can be posted"
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
            local proj_name="${row%%${FS}*}" rest="${row#*${FS}}"
            print_table_line "$(display_text "$(basename "$proj_name")")" "$(display_text "$rest")"
        done
    fi
    print -r -- ""

    print -r -- "Hooks"
    if ((${#HOOKS[@]} == 0)); then print -r -- "  none"; else
        for row in "${HOOKS[@]}"; do
            local event="${row%%${FS}*}" rest="${row#*${FS}}"
            print_table_line "$event" "$(display_text "$rest")"
        done
    fi
    print -r -- ""

    print -r -- "Plugins"
    if ((${#PLUGINS[@]} == 0)); then print -r -- "  none"; else
        for row in "${PLUGINS[@]}"; do
            local pn="${row%%${FS}*}" rest="${row#*${FS}}"
            print_table_line "$pn" "$(display_text "$rest")"
        done
    fi
    print -r -- ""

    print -r -- "Skills / Agents"
    if ((${#SKILLS[@]} == 0)); then print -r -- "  none"; else
        for row in "${SKILLS[@]}"; do
            local sn="${row%%${FS}*}" rest="${row#*${FS}}"
            print_table_line "$sn" "$(display_text "$rest")"
        done
    fi
    print -r -- ""

    print -r -- "Background Monitors"
    if ((${#MONITORS[@]} == 0)); then print -r -- "  none"; else
        for row in "${MONITORS[@]}"; do
            local mn="${row%%${FS}*}" rest="${row#*${FS}}"
            print_table_line "$mn" "$(display_text "$rest")"
        done
    fi
    print -r -- ""

    print -r -- "Security Settings"
    if ((${#SECURITY_SETTINGS[@]} == 0)); then print -r -- "  none"; else
        for row in "${SECURITY_SETTINGS[@]}"; do
            local kn="${row%%${FS}*}" rest="${row#*${FS}}"
            print_table_line "$kn" "$(display_text "$rest")"
        done
    fi
    print -r -- ""

    print -r -- "Active Sessions"
    if ((${#ACTIVE_SESSIONS[@]} == 0)); then print -r -- "  none"; else
        for row in "${ACTIVE_SESSIONS[@]}"; do
            local pid="${row%%${FS}*}" rest="${row#*${FS}}"
            print_table_line "pid=$pid" "$(display_text "$rest")"
        done
    fi
    print -r -- ""

    print -r -- "Sensitive Files"
    if ((${#SENSITIVE_FILES[@]} == 0)); then print -r -- "  none"; else
        for row in "${SENSITIVE_FILES[@]}"; do
            local n="${row%%${FS}*}" rest="${row#*${FS}}"
            print_table_line "$n" "$(display_text "$rest")"
        done
    fi
    print -r -- ""

    print -r -- "Retention"
    if ((${#RETENTION_ITEMS[@]} == 0)); then print -r -- "  none"; else
        for row in "${RETENTION_ITEMS[@]}"; do
            local n="${row%%${FS}*}" rest="${row#*${FS}}"
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

# Pick the nth |-delimited field out of a packed inventory row.
# NOTE: the assignments must stay on separate lines. In zsh the right-hand sides
# of a single `local a=$1 b=$a` are expanded before any assignment takes effect,
# so `rest` would silently pick up an outer variable instead of `row`.
json_split_field() {
    local row="$1" n="$2"
    local rest="$row"
    local i
    for ((i=1; i<n; i++)); do
        rest="${rest#*${FS}}"
    done
    printf '%s' "${rest%%${FS}*}"
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
        projects+="{\"path\":$(jstr_out "$(json_split_field "$row" 1)"),\"detail\":$(jstr_out "${row#*${FS}}")}"
        ((idx++))
    done
    projects+="]"

    local hooks="[" idx=0
    for row in "${HOOKS[@]}"; do
        ((idx > 0)) && hooks+=","
        hooks+="{\"event\":$(jstr "$(json_split_field "$row" 1)"),\"source\":$(jstr "$(json_split_field "$row" 2)"),\"type\":$(jstr "$(json_split_field "$row" 3)"),\"matcher\":$(jstr "$(json_split_field "$row" 4)"),\"command\":$(jstr_out "$(json_split_field "$row" 5)"),\"risk_tags\":$(jstr "$(json_split_field "$row" 6)")}"
        ((idx++))
    done
    hooks+="]"

    local plugins="[" idx=0
    for row in "${PLUGINS[@]}"; do
        ((idx > 0)) && plugins+=","
        plugins+="{\"name\":$(jstr_out "$(json_split_field "$row" 1)"),\"state\":$(jstr "$(json_split_field "$row" 2)"),\"scope\":$(jstr "$(json_split_field "$row" 3)"),\"provenance\":$(jstr "$(json_split_field "$row" 4)"),\"components\":$(jstr "$(json_split_field "$row" 5)"),\"version\":$(jstr "$(json_split_field "$row" 6)"),\"author\":$(jstr_out "$(json_split_field "$row" 7)"),\"path\":$(jstr_out "$(json_split_field "$row" 8)")}"
        ((idx++))
    done
    plugins+="]"

    local skills="[" idx=0
    for row in "${SKILLS[@]}"; do
        ((idx > 0)) && skills+=","
        skills+="{\"name\":$(jstr_out "$(json_split_field "$row" 1)"),\"kind\":$(jstr "$(json_split_field "$row" 2)"),\"source\":$(jstr_out "$(json_split_field "$row" 3)"),\"description\":$(jstr "$(json_split_field "$row" 4)"),\"tools\":$(jstr "$(json_split_field "$row" 5)"),\"path\":$(jstr_out "$(json_split_field "$row" 6)")}"
        ((idx++))
    done
    skills+="]"

    local monitors="[" idx=0
    for row in "${MONITORS[@]}"; do
        ((idx > 0)) && monitors+=","
        monitors+="{\"name\":$(jstr "$(json_split_field "$row" 1)"),\"plugin\":$(jstr_out "$(json_split_field "$row" 2)"),\"when\":$(jstr "$(json_split_field "$row" 3)"),\"command\":$(jstr_out "$(json_split_field "$row" 4)"),\"description\":$(jstr "$(json_split_field "$row" 5)")}"
        ((idx++))
    done
    monitors+="]"

    local sec_settings="[" idx=0
    for row in "${SECURITY_SETTINGS[@]}"; do
        ((idx > 0)) && sec_settings+=","
        sec_settings+="{\"key\":$(jstr "$(json_split_field "$row" 1)"),\"value\":$(jstr_out "$(json_split_field "$row" 2)"),\"source\":$(jstr "$(json_split_field "$row" 3)")}"
        ((idx++))
    done
    sec_settings+="]"

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

    printf '{"timestamp":%s,"hostname":%s,"username":%s,"claude_dir":%s,"summary":{"warn":%d,"review":%d,"info":%d},"findings":%s,"mcp_servers":%s,"projects":%s,"hooks":%s,"plugins":%s,"skills":%s,"monitors":%s,"security_settings":%s,"active_sessions":%s,"sensitive_files":%s,"retention":%s}' \
        "$(jstr "$TIMESTAMP")" "$(jstr "$HOSTNAME_VAL")" "$(jstr_out "$AUDIT_USER")" "$(jstr_out "$CLAUDE_DIR")" \
        "$WARN_COUNT" "$REVIEW_COUNT" "$INFO_COUNT" "$findings" "$mcp" \
        "$projects" "$hooks" "$plugins" "$skills" "$monitors" "$sec_settings" "$sessions" "$sens_files" "$retention"
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
            first="${row%%${FS}*}"
            rest="${row#*${FS}}"
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
    html_list_rows "Plugins" "${PLUGINS[@]}"
    html_list_rows "Skills / Agents" "${SKILLS[@]}"
    html_list_rows "Background Monitors" "${MONITORS[@]}"
    html_list_rows "Security Settings" "${SECURITY_SETTINGS[@]}"
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
        collect_managed_settings
        collect_settings
        collect_project_settings
        collect_plugins
        collect_skills
        collect_desktop_config
        collect_sensitive_files
        collect_retention
        collect_runtime
        finalize_cross_checks
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
