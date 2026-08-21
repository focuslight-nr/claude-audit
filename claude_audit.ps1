# CLAUDE-AUDIT - Claude Code local security audit tool (Windows/PowerShell)
# Read-only audit for Claude Code and Claude Desktop configuration.
# Unofficial project. Not affiliated with, endorsed by, sponsored by, or maintained by Anthropic.
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CliArgs
)

$ErrorActionPreference = 'Stop'
$script:Version = '0.2.0'

$script:DangerousMcpHints = @(
    'bash', 'sh', 'zsh', 'cmd', 'cmd.exe', 'powershell', 'powershell.exe',
    'pwsh', 'pwsh.exe', 'python', 'python.exe', 'python3', 'node', 'node.exe',
    'ruby', 'perl', 'wscript', 'wscript.exe', 'cscript', 'cscript.exe',
    'mshta', 'mshta.exe', 'curl', 'curl.exe', 'wget', 'sqlite3', 'psql',
    'mysql', 'ssh', 'scp'
)

$script:SensitiveNameRegex = '(?i)(token|secret|password|passwd|api[_-]?key|credential|auth|session|cookie)'

# Hook events known to Claude Code 2.1.x. Unknown names are reported as INFO so the
# tool degrades gracefully when Anthropic adds new events.
$script:KnownHookEvents = @(
    'SessionStart', 'Setup', 'UserPromptSubmit', 'UserPromptExpansion', 'PreToolUse',
    'PermissionRequest', 'PermissionDenied', 'PostToolUse', 'PostToolUseFailure',
    'PostToolBatch', 'Notification', 'MessageDisplay', 'SubagentStart', 'SubagentStop',
    'TaskCreated', 'TaskCompleted', 'Stop', 'StopFailure', 'TeammateIdle',
    'InstructionsLoaded', 'ConfigChange', 'CwdChanged', 'DirectoryAdded', 'FileChanged',
    'WorktreeCreate', 'WorktreeRemove', 'PreCompact', 'PostCompact', 'Elicitation',
    'ElicitationResult', 'SessionEnd'
)

# Marketplaces published by Anthropic; anything else is third-party code.
$script:OfficialMarketplaces = @(
    'claude-plugins-official', 'claude-community',
    'anthropics/claude-plugins-official', 'anthropics/claude-plugins-community', 'inline'
)

# Managed (enterprise policy) settings locations - Windows.
# The registry keys have no macOS equivalent; the JSON paths mirror the macOS ones.
$script:ManagedSettingsFile = Join-Path ${env:ProgramFiles} 'ClaudeCode\managed-settings.json'
$script:ManagedSettingsDir = Join-Path ${env:ProgramFiles} 'ClaudeCode\managed-settings.d'
$script:ManagedRegistryKeys = @(
    'HKLM:\SOFTWARE\Policies\ClaudeCode',
    'HKCU:\SOFTWARE\Policies\ClaudeCode'
)

$script:Options = @{
    Json = $false
    Html = $null
    Summary = $false
    Output = $null
    FailOn = $null
    RedactPaths = $false
    User = $null
    AllUsers = $false
    ClaudeDir = $null
    Quiet = $false
}

function Show-Usage {
    @"
CLAUDE-AUDIT v$($script:Version) - Claude Code local security audit
Usage: .\claude_audit.ps1 [--html [FILE]] [--json] [--summary] [--output FILE]
       [--fail-on warn|review] [--redact-paths] [--user USER] [--all-users]
       [--claude-dir DIR] [-q|--quiet] [--version] [-h|--help]
"@
}

function Exit-ArgumentError([string]$Message) {
    [Console]::Error.WriteLine("Error: $Message")
    [Console]::Error.WriteLine((Show-Usage))
    exit 1
}

for ($i = 0; $i -lt $CliArgs.Count; $i++) {
    $arg = $CliArgs[$i]
    switch ($arg) {
        '--json' { $script:Options.Json = $true }
        '--summary' { $script:Options.Summary = $true }
        '--redact-paths' { $script:Options.RedactPaths = $true }
        '--all-users' { $script:Options.AllUsers = $true }
        '--quiet' { $script:Options.Quiet = $true }
        '-q' { $script:Options.Quiet = $true }
        '--version' { Write-Output "CLAUDE-AUDIT v$($script:Version)"; exit 0 }
        '--help' { Write-Output (Show-Usage); exit 0 }
        '-h' { Write-Output (Show-Usage); exit 0 }
        '--html' {
            if (($i + 1) -lt $CliArgs.Count -and -not $CliArgs[$i + 1].StartsWith('-')) {
                $i++
                $script:Options.Html = $CliArgs[$i]
            } else {
                $script:Options.Html = 'AUTO'
            }
        }
        { $_ -in @('--output', '--fail-on', '--user', '--claude-dir') } {
            if (($i + 1) -ge $CliArgs.Count) { Exit-ArgumentError "Missing value for $arg" }
            $i++
            $value = $CliArgs[$i]
            switch ($arg) {
                '--output' { $script:Options.Output = $value }
                '--fail-on' { $script:Options.FailOn = $value.ToLowerInvariant() }
                '--user' { $script:Options.User = $value }
                '--claude-dir' { $script:Options.ClaudeDir = $value }
            }
        }
        default { Exit-ArgumentError "Unknown option: $arg" }
    }
}

if ($script:Options.Json -and $script:Options.Html) {
    Exit-ArgumentError '--json and --html are mutually exclusive'
}
if ($script:Options.AllUsers -and $script:Options.User) {
    Exit-ArgumentError '--user and --all-users are mutually exclusive'
}
if ($script:Options.AllUsers -and $script:Options.ClaudeDir) {
    Exit-ArgumentError '--claude-dir and --all-users are mutually exclusive'
}
if ($script:Options.ClaudeDir -and -not (Test-Path -LiteralPath $script:Options.ClaudeDir -PathType Container)) {
    Exit-ArgumentError "--claude-dir does not exist: $($script:Options.ClaudeDir)"
}
if (-not $script:Options.Html -and $script:Options.Output -and
    [IO.Path]::GetExtension($script:Options.Output) -ieq '.html') {
    Exit-ArgumentError '--output .html requires --html'
}
if ($script:Options.FailOn -and $script:Options.FailOn -notin @('warn', 'review')) {
    Exit-ArgumentError "--fail-on must be 'warn' or 'review'"
}

function New-AuditState([string]$UserName, [string]$HomeDir, [string]$ClaudeDir) {
    @{
        User = $UserName
        Home = $HomeDir
        ClaudeDir = $ClaudeDir
        Timestamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        Hostname = [Environment]::MachineName
        Findings = [Collections.Generic.List[object]]::new()
        McpServers = [Collections.Generic.List[object]]::new()
        Projects = [Collections.Generic.List[object]]::new()
        Hooks = [Collections.Generic.List[object]]::new()
        Plugins = [Collections.Generic.List[object]]::new()
        Skills = [Collections.Generic.List[object]]::new()
        Monitors = [Collections.Generic.List[object]]::new()
        SecuritySettings = [Collections.Generic.List[object]]::new()
        ActiveSessions = [Collections.Generic.List[object]]::new()
        SensitiveFiles = [Collections.Generic.List[object]]::new()
        Retention = [Collections.Generic.List[object]]::new()
        SeenMcp = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        SeenPlugin = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    }
}

function Add-Finding {
    param($State, [string]$Severity, [string]$Section, [string]$Message, [string]$Detail = '')
    $State.Findings.Add([pscustomobject]@{
        severity = $Severity
        section = $Section
        message = $Message
        detail = $Detail
    })
}

function Get-Summary($State) {
    [ordered]@{
        warn = @($State.Findings | Where-Object severity -eq 'WARN').Count
        review = @($State.Findings | Where-Object severity -eq 'REVIEW').Count
        info = @($State.Findings | Where-Object severity -eq 'INFO').Count
    }
}

function Get-DisplayText($State, [AllowNull()][object]$Value) {
    $text = if ($null -eq $Value) { '' } else { [string]$Value }
    if ($script:Options.RedactPaths) {
        if ($State.Home) { $text = $text.Replace($State.Home, '~') }
        if ($State.User) {
            $text = $text -replace "(?i)(C:\\Users\\)$([regex]::Escape($State.User))", '$1[USER]'
        }
    }
    $text
}

function Read-JsonFile([string]$Path) {
    try {
        Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        $null
    }
}

function Get-Property($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    if ($Object -is [array] -or $Object -is [ValueType] -or $Object -is [string]) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    $null
}

# Walk a dotted path (e.g. "sandbox.filesystem.disabled") and return the leaf value.
function Get-PropertyPath($Object, [string]$Path) {
    $current = $Object
    foreach ($part in $Path.Split('.')) {
        $current = Get-Property $current $part
        if ($null -eq $current) { return $null }
    }
    $current
}

# Scalar helper: empty string for absent/null values, so callers can test with `if`.
function Get-Scalar($Object, [string]$Path) {
    $value = Get-PropertyPath $Object $Path
    if ($null -eq $value) { return '' }
    if ($value -is [bool]) { return $value.ToString().ToLowerInvariant() }
    [string]$value
}

function Get-ObjectEntries($Object) {
    if ($null -eq $Object) { return @() }
    # Arrays and scalars have no named entries; only JSON objects do.
    if ($Object -is [array] -or $Object -is [ValueType] -or $Object -is [string]) { return @() }
    @($Object.PSObject.Properties | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; Value = $_.Value }
    })
}

function Join-Values($Value) {
    if ($null -eq $Value) { return '' }
    @($Value) -join ', '
}

function Get-KeyNames($Object) {
    (Get-ObjectEntries $Object | ForEach-Object Name) -join ', '
}

# Permission lists routinely run to thousands of characters. Keep the count,
# which is what matters, and only a readable preview of the entries.
function Get-ListSummary([string]$Text, [int]$Count) {
    if (-not $Text) { return '' }
    $max = 360
    if ($Text.Length -gt $max) {
        return "$Count entries: $($Text.Substring(0, $max)) ...(truncated)"
    }
    "$Count entries: $Text"
}

function Get-Truncated([AllowNull()][string]$Text, [int]$Length) {
    if (-not $Text) { return '' }
    if ($Text.Length -le $Length) { return $Text }
    $Text.Substring(0, $Length)
}

function Get-FileAclSummary([string]$Path) {
    try {
        $acl = Get-Acl -LiteralPath $Path
        $owner = $acl.Owner
        $broad = @($acl.Access | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            $_.IdentityReference.Value -match '(?i)(Everyone|BUILTIN\\Users|Authenticated Users)' -and
            ($_.FileSystemRights.ToString() -match '(?i)(Read|Write|Modify|FullControl)')
        })
        [pscustomobject]@{
            Summary = "owner=$owner; broad_access=$($broad.Count)"
            IsBroad = $broad.Count -gt 0
        }
    } catch {
        [pscustomobject]@{ Summary = 'ACL unavailable'; IsBroad = $false }
    }
}

function Add-SensitiveFile($State, [string]$Name, [string]$Path, [ValidateSet('', 'WARN', 'REVIEW')][string]$BroadSeverity = '') {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $acl = Get-FileAclSummary $Path
    $State.SensitiveFiles.Add([pscustomobject]@{
        name = $Name
        mode = $acl.Summary
        path = $Path
    })
    if ($BroadSeverity -and $acl.IsBroad) {
        Add-Finding $State $BroadSeverity 'Sensitive Files' "$Name grants access to broad Windows principals" "$($acl.Summary); path=$Path"
    }
}

# Record a security-relevant setting so it lands in the report inventory.
function Add-SecuritySetting {
    param($State, [string]$Key, [string]$Value, [string]$Source, [string]$Severity = '', [string]$Message = '')
    $State.SecuritySettings.Add([pscustomobject]@{
        key = $Key
        value = $Value
        source = $Source
    })
    if ($Severity) {
        $text = if ($Message) { $Message } else { "$Key = $Value" }
        Add-Finding $State $Severity 'Settings' $text "source=$Source; $Key=$Value"
    }
}

function Get-McpEnvRiskTags([string]$Keys) {
    $tags = [Collections.Generic.List[string]]::new()
    if ($Keys -match '(?i)(token|secret|password|passwd|api[_-]?key|credential|auth|cookie)') { $tags.Add('secret-like-env') }
    if ($Keys -match '(?i)(trusted|allowlist)') { $tags.Add('trust-or-allowlist') }
    if ($Keys -match '(?i)(path|dirs|home)') { $tags.Add('filesystem-scope') }
    if ($Keys -match '(?i)(browser|backend)') { $tags.Add('browser-scope') }
    $tags -join ','
}

# Risk tags for a hook. Handles every hook type supported by Claude Code 2.1.x:
# command, http, mcp_tool, prompt, agent.
function Get-HookRiskTags {
    param([string]$Descriptor, [string]$Type = 'command', [string]$Headers = '', [bool]$Async = $false)
    $tags = [Collections.Generic.List[string]]::new()
    switch ($Type) {
        'http' {
            $tags.Add('http-endpoint')
            # A hook posting session data off-box is materially different from a local one.
            if ($Descriptor -notmatch '(?i)^https?://(localhost|127\.0\.0\.1)') { $tags.Add('remote-endpoint') }
            if ($Descriptor -match '(?i)^http://') { $tags.Add('cleartext-http') }
            if ($Headers -match '(?i)(authorization|token|api[_-]?key|secret|cookie)') { $tags.Add('credential-header') }
        }
        'mcp_tool' { $tags.Add('mcp-tool-invocation') }
        'prompt' { $tags.Add('model-invocation') }
        'agent' { $tags.Add('model-invocation') }
    }
    if ($Type -eq 'command') {
        if ($Descriptor -match '(?i)(curl|wget|https?://|Invoke-WebRequest|Invoke-RestMethod|\bnc\b)') { $tags.Add('network') }
        if ($Descriptor -match '(?i)(\brm\b|Remove-Item|\bdel\b|\berase\b|\brmdir\b|truncate)') { $tags.Add('destructive') }
        if ($Descriptor -match '(?i)git\s+(push|commit)') { $tags.Add('git-write') }
        if ($Descriptor -match '(?i)(Start-Process|mshta|wscript|cscript)') { $tags.Add('gui-or-script-host') }
        if ($Descriptor -match '(?i)(RunAs|\bsudo\b)') { $tags.Add('elevated-privilege') }
        if ($Descriptor -match '(?i)(Invoke-Expression|\biex\b|FromBase64String|EncodedCommand|\|\s*(sh|bash)\b|\beval\b)') { $tags.Add('dynamic-code-execution') }
    }
    if ($Async) { $tags.Add('async-background') }
    $tags -join ','
}

function Get-RedactedValue([string]$Key, [AllowNull()][object]$Value) {
    $text = if ($null -eq $Value) { '' } else { [string]$Value }
    if ($Key -match $script:SensitiveNameRegex -or
        $text -match '(?i)(sk-ant-|bearer |token=|secret=|password=|api[_-]?key=)') {
        return '[REDACTED]'
    }
    $text
}

# Classify a plugin marketplace as Anthropic-published or third-party.
function Get-PluginProvenance([string]$Marketplace) {
    if ($Marketplace -and ($script:OfficialMarketplaces -contains $Marketplace)) { return 'anthropic-published' }
    if ($Marketplace -eq 'skills-dir') { return 'local-skills-dir' }
    if (-not $Marketplace) { return 'unknown' }
    'third-party'
}

function Format-Bytes([long]$Bytes) {
    if ($Bytes -lt 1KB) { return "$Bytes B" }
    if ($Bytes -lt 1MB) { return '{0:N1} KB' -f ($Bytes / 1KB) }
    if ($Bytes -lt 1GB) { return '{0:N1} MB' -f ($Bytes / 1MB) }
    '{0:N1} GB' -f ($Bytes / 1GB)
}

function Get-DirectoryStats([string]$Path) {
    try {
        $files = @(Get-ChildItem -LiteralPath $Path -File -Recurse -Force -ErrorAction SilentlyContinue)
        $latest = $files | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
        [pscustomobject]@{
            Count = $files.Count
            Bytes = [long](($files | Measure-Object Length -Sum).Sum)
            Latest = if ($latest) { $latest.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' }
        }
    } catch {
        [pscustomobject]@{ Count = 0; Bytes = 0L; Latest = '' }
    }
}

# Wildcard lookups must not throw when an intermediate directory is missing.
function Get-MatchingFiles([string]$Pattern) {
    @(Get-ChildItem -Path $Pattern -File -Force -ErrorAction SilentlyContinue)
}

function Get-MatchingDirectories([string]$Pattern) {
    @(Get-ChildItem -Path $Pattern -Directory -Force -ErrorAction SilentlyContinue)
}

function Add-McpServersFromJson($State, [string]$Path, [string]$Source) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $json = Read-JsonFile $Path
    if ($null -eq $json) {
        Add-Finding $State 'REVIEW' 'Config' 'Unable to parse JSON configuration' $Path
        return
    }
    Add-McpServersFromObject $State (Get-Property $json 'mcpServers') $Source
}

function Add-McpServersFromObject($State, $ServersObject, [string]$Source) {
    foreach ($entry in (Get-ObjectEntries $ServersObject)) {
        $server = $entry.Value
        $key = "$($entry.Name)|$Source"
        if (-not $State.SeenMcp.Add($key)) { continue }
        $commandValue = Get-Property $server 'command'
        if (-not $commandValue) { $commandValue = Get-Property $server 'url' }
        $command = [string]$commandValue
        $argText = Join-Values (Get-Property $server 'args')
        $envKeys = Get-KeyNames (Get-Property $server 'env')
        $type = [string](Get-Property $server 'type')
        if (-not $type) { $type = 'stdio' }
        $riskTags = Get-McpEnvRiskTags $envKeys
        $State.McpServers.Add([pscustomobject]@{
            name = "$($entry.Name)($Source)"
            type = $type
            command = Get-RedactedValue 'command' $command
            args = Get-RedactedValue 'args' $argText
            env_keys = $envKeys
            env_risk_tags = $riskTags
        })
        Add-Finding $State 'REVIEW' 'MCP Servers' "MCP server configured: $($entry.Name)" "source=$Source; type=$type; command=$(if ($command) {$command} else {'unknown'}); env_keys=$(if ($envKeys) {$envKeys} else {'none'})"
        if ($riskTags) {
            Add-Finding $State 'REVIEW' 'MCP Servers' "MCP server env keys imply elevated scope: $($entry.Name)" $riskTags
        }
        if ($command) {
            $base = [IO.Path]::GetFileName($command).ToLowerInvariant()
            if ($base -in $script:DangerousMcpHints) {
                Add-Finding $State 'WARN' 'MCP Servers' "MCP server uses command-capable runtime: $($entry.Name)" $command
            }
        }
    }
}

# Describe one hook object: what it actually invokes.
function Get-HookDescriptor($Hook) {
    if ($Hook -is [string]) { return $Hook }
    $command = Get-Property $Hook 'command'
    if ($command) {
        $hookArgs = Get-Property $Hook 'args'
        if ($hookArgs) { return "$command $((@($hookArgs) | ForEach-Object { [string]$_ }) -join ' ')" }
        return [string]$command
    }
    $url = Get-Property $Hook 'url'
    if ($url) { return [string]$url }
    $server = Get-Property $Hook 'server'
    if ($server) {
        $tool = Get-Property $Hook 'tool'
        if (-not $tool) { $tool = '?' }
        return "$server`:$tool"
    }
    $prompt = Get-Property $Hook 'prompt'
    if ($prompt) { return (Get-Truncated ([string]$prompt) 160) }
    '(unspecified)'
}

function Get-HookType($Hook) {
    if ($Hook -is [string]) { return 'command' }
    $type = [string](Get-Property $Hook 'type')
    if ($type) { return $type }
    'command'
}

# Extract every hook from a settings file or a plugin hooks.json, covering all
# hook types (command, http, mcp_tool, prompt, agent) and matcher groups.
function Add-HooksFromObject($State, $HooksObject, [string]$Source) {
    foreach ($event in (Get-ObjectEntries $HooksObject)) {
        $eventName = $event.Name
        foreach ($entry in @($event.Value)) {
            $matcher = '*'
            $hooks = @($entry)
            $nested = Get-Property $entry 'hooks'
            if ($null -ne $nested) {
                $entryMatcher = [string](Get-Property $entry 'matcher')
                if ($entryMatcher) { $matcher = $entryMatcher }
                $hooks = @($nested)
            }
            foreach ($hook in $hooks) {
                if ($null -eq $hook) { continue }
                $type = Get-HookType $hook
                $descriptor = Get-HookDescriptor $hook
                $async = (Get-Property $hook 'async') -eq $true
                $headers = Get-KeyNames (Get-Property $hook 'headers')
                $risk = Get-HookRiskTags -Descriptor $descriptor -Type $type -Headers $headers -Async $async
                $State.Hooks.Add([pscustomobject]@{
                    event = $eventName
                    source = $Source
                    type = $type
                    matcher = $matcher
                    command = $descriptor
                    risk_tags = $risk
                })
                $short = Get-Truncated $descriptor 90
                Add-Finding $State 'REVIEW' 'Hooks' "Hook configured: $eventName ($type)" `
                    "source=$Source; matcher=$matcher; target=$short$(if ($risk) {"; risk=$risk"})"
                if ($risk) {
                    Add-Finding $State 'WARN' 'Hooks' "Hook has elevated risk: $eventName ($type)" "risk=$risk; target=$short"
                }
            }
        }
        if ($script:KnownHookEvents -notcontains $eventName) {
            Add-Finding $State 'INFO' 'Hooks' "Unrecognized hook event name: $eventName" `
                "source=$Source; not in the known event list for Claude Code 2.1.x"
        }
    }
}

function Add-HooksFromJson($State, [string]$Path, [string]$Source) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $json = Read-JsonFile $Path
    if ($null -eq $json) { return }
    $hooks = Get-Property $json 'hooks'
    if ($null -eq $hooks) { $hooks = $json }
    Add-HooksFromObject $State $hooks $Source
}

function Collect-SettingsFile($State, [string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $json = Read-JsonFile $Path
    if ($null -eq $json) {
        Add-Finding $State 'REVIEW' 'Config' 'Unable to parse JSON configuration' $Path
        return
    }

    Add-McpServersFromObject $State (Get-Property $json 'mcpServers') $Label
    Add-HooksFromObject $State (Get-Property $json 'hooks') $Label

    # ---- Permissions -------------------------------------------------------
    $permissions = Get-Property $json 'permissions'
    $allowList = @(Get-Property $permissions 'allow')
    $askList = @(Get-Property $permissions 'ask')
    $denyList = @(Get-Property $permissions 'deny')
    $allowed = Join-Values (Get-Property $permissions 'allow')
    $asked = Join-Values (Get-Property $permissions 'ask')
    $denied = Join-Values (Get-Property $permissions 'deny')
    if ($allowed) {
        Add-Finding $State 'REVIEW' 'Permissions' "Pre-approved tools in settings ($Label)" (Get-ListSummary $allowed $allowList.Count)
    }
    if ($asked) {
        Add-Finding $State 'INFO' 'Permissions' "Tools requiring confirmation ($Label)" (Get-ListSummary $asked $askList.Count)
    }
    if ($denied) {
        Add-Finding $State 'INFO' 'Permissions' "Denied tools in settings ($Label)" (Get-ListSummary $denied $denyList.Count)
    }
    $defaultMode = Get-Scalar $permissions 'defaultMode'
    if ($defaultMode) {
        if ($defaultMode -eq 'auto') {
            Add-SecuritySetting $State 'permissions.defaultMode' $defaultMode $Label 'WARN' `
                "Default permission mode is 'auto' (actions auto-approved without prompting)"
        } else {
            Add-SecuritySetting $State 'permissions.defaultMode' $defaultMode $Label 'INFO' `
                "Default permission mode: $defaultMode"
        }
    }
    $extraDirs = Join-Values (Get-Property $permissions 'additionalDirectories')
    if ($extraDirs) {
        Add-SecuritySetting $State 'permissions.additionalDirectories' $extraDirs $Label 'WARN' `
            'Additional directories are trusted beyond the workspace'
    }
    $disableAuto = Get-Scalar $permissions 'disableAutoMode'
    if ($disableAuto) {
        Add-SecuritySetting $State 'permissions.disableAutoMode' $disableAuto $Label 'INFO' 'Auto mode is disabled by policy'
    }

    # ---- Credential-producing helpers (these execute external commands) -----
    $keyHelper = Get-Scalar $json 'apiKeyHelper'
    if ($keyHelper) {
        Add-SecuritySetting $State 'apiKeyHelper' $keyHelper $Label 'WARN' 'apiKeyHelper runs an external command to mint API credentials'
    }
    $awsExport = Get-Scalar $json 'awsCredentialExport'
    if ($awsExport) {
        Add-SecuritySetting $State 'awsCredentialExport' $awsExport $Label 'WARN' 'awsCredentialExport runs an external script that outputs AWS credentials'
    }
    $awsRefresh = Get-Scalar $json 'awsAuthRefresh'
    if ($awsRefresh) {
        Add-SecuritySetting $State 'awsAuthRefresh' $awsRefresh $Label 'WARN' 'awsAuthRefresh runs an external script that modifies the .aws directory'
    }

    # ---- Injected environment variables ------------------------------------
    # Key names only - values may hold secrets and are never read.
    $envKeys = Get-KeyNames (Get-Property $json 'env')
    if ($envKeys) {
        $State.SecuritySettings.Add([pscustomobject]@{ key = 'env'; value = $envKeys; source = $Label })
        if ($envKeys -match $script:SensitiveNameRegex) {
            Add-Finding $State 'WARN' 'Settings' "Injected env vars include secret-like names ($Label)" "keys=$envKeys"
        } else {
            Add-Finding $State 'REVIEW' 'Settings' "Environment variables are injected into every session ($Label)" "keys=$envKeys"
        }
    }

    # ---- Sandbox isolation --------------------------------------------------
    if ((Get-Scalar $json 'sandbox.filesystem.disabled') -eq 'true') {
        Add-SecuritySetting $State 'sandbox.filesystem.disabled' 'true' $Label 'WARN' 'Sandbox filesystem isolation is DISABLED'
    }
    if ((Get-Scalar $json 'sandbox.network.disabled') -eq 'true') {
        Add-SecuritySetting $State 'sandbox.network.disabled' 'true' $Label 'WARN' 'Sandbox network isolation is DISABLED'
    }
    $credRules = @(Get-PropertyPath $json 'sandbox.credentials').Count
    if ($credRules -gt 0) {
        Add-SecuritySetting $State 'sandbox.credentials' "$credRules rule(s)" $Label 'INFO' "Sandbox credential masking rules configured: $credRules"
    }

    # ---- Hook controls ------------------------------------------------------
    if ((Get-Scalar $json 'disableAllHooks') -eq 'true') {
        Add-SecuritySetting $State 'disableAllHooks' 'true' $Label 'INFO' 'All hooks and custom status lines are disabled'
    }
    $httpAllow = Join-Values (Get-Property $json 'allowedHttpHookUrls')
    if ($httpAllow) {
        Add-SecuritySetting $State 'allowedHttpHookUrls' $httpAllow $Label 'INFO' 'HTTP hook URL allowlist is configured'
    }
    $httpEnv = Join-Values (Get-Property $json 'httpHookAllowedEnvVars')
    if ($httpEnv) {
        Add-SecuritySetting $State 'httpHookAllowedEnvVars' $httpEnv $Label 'INFO' 'HTTP hook header env-var allowlist is configured'
    }

    # ---- Status line (executes a command each render) -----------------------
    $statusLine = Get-Property $json 'statusLine'
    if ($null -ne $statusLine) {
        $statusCommand = if ($statusLine -is [string]) { $statusLine } else { [string](Get-Property $statusLine 'command') }
        if ($statusCommand) {
            Add-SecuritySetting $State 'statusLine' $statusCommand $Label 'REVIEW' 'Custom status line executes a command'
        }
    }

    # ---- Plugins and marketplaces ------------------------------------------
    foreach ($plugin in (Get-ObjectEntries (Get-Property $json 'enabledPlugins'))) {
        $pluginName = $plugin.Name
        $pluginState = if ($plugin.Value -eq $true) { 'true' } else { 'false' }
        $marketplace = ''
        if ($pluginName -like '*@*') { $marketplace = $pluginName.Substring($pluginName.LastIndexOf('@') + 1) }
        $provenance = Get-PluginProvenance $marketplace
        $State.Plugins.Add([pscustomobject]@{
            name = $pluginName
            state = $pluginState
            scope = $Label
            provenance = $provenance
            components = '(declared in settings)'
            version = 'unknown'
            author = 'unknown'
            path = ''
        })
        if ($pluginState -eq 'true') {
            if ($provenance -in @('third-party', 'unknown')) {
                Add-Finding $State 'WARN' 'Plugins' "Enabled plugin from a non-Anthropic marketplace: $pluginName" "source=$Label; provenance=$provenance"
            } else {
                Add-Finding $State 'REVIEW' 'Plugins' "Enabled plugin: $pluginName" "source=$Label; provenance=$provenance"
            }
        }
    }

    $extraMarkets = Get-Property $json 'extraKnownMarketplaces'
    $extraMarketText = if ($extraMarkets -is [array]) { Join-Values $extraMarkets } else { Get-KeyNames $extraMarkets }
    if ($extraMarketText) {
        Add-SecuritySetting $State 'extraKnownMarketplaces' $extraMarketText $Label 'WARN' 'Additional (non-Anthropic) plugin marketplaces are trusted'
    }
    if ((Get-Scalar $json 'strictKnownMarketplaces') -eq 'true') {
        Add-SecuritySetting $State 'strictKnownMarketplaces' 'true' $Label 'INFO' 'Plugin installs are restricted to known marketplaces'
    }
    $blockedMarkets = Join-Values (Get-Property $json 'blockedMarketplaces')
    if ($blockedMarkets) {
        Add-SecuritySetting $State 'blockedMarketplaces' $blockedMarkets $Label 'INFO' 'Blocked plugin marketplaces are configured'
    }
    if ((Get-Scalar $json 'disableSideloadFlags') -eq 'true') {
        Add-SecuritySetting $State 'disableSideloadFlags' 'true' $Label 'INFO' 'Plugin/MCP sideload CLI flags are rejected'
    }
    if ((Get-Scalar $json 'disableCommandPluginSources') -eq 'true') {
        Add-SecuritySetting $State 'disableCommandPluginSources' 'true' $Label 'INFO' 'Command-sourced plugins are blocked'
    }

    # ---- MCP governance -----------------------------------------------------
    $mcpAllow = (@(Get-Property $json 'allowedMcpServers') | ForEach-Object {
        if ($_ -is [psobject] -and (Get-Property $_ 'serverName')) { [string](Get-Property $_ 'serverName') } else { [string]$_ }
    }) -join ', '
    $mcpDeny = (@(Get-Property $json 'deniedMcpServers') | ForEach-Object {
        if ($_ -is [psobject] -and (Get-Property $_ 'serverName')) { [string](Get-Property $_ 'serverName') } else { [string]$_ }
    }) -join ', '
    $mcpDisabled = Join-Values (Get-Property $json 'disabledMcpjsonServers')
    if ($mcpAllow) { Add-SecuritySetting $State 'allowedMcpServers' $mcpAllow $Label 'INFO' "MCP server allowlist: $mcpAllow" }
    if ($mcpDeny) { Add-SecuritySetting $State 'deniedMcpServers' $mcpDeny $Label 'INFO' "MCP server denylist: $mcpDeny" }
    if ($mcpDisabled) { Add-SecuritySetting $State 'disabledMcpjsonServers' $mcpDisabled $Label 'INFO' "Rejected .mcp.json servers: $mcpDisabled" }
    if ((Get-Scalar $json 'disableClaudeAiConnectors') -eq 'true') {
        Add-SecuritySetting $State 'disableClaudeAiConnectors' 'true' $Label 'INFO' 'claude.ai MCP connectors are disabled'
    }
    if ((Get-Scalar $json 'allowAllClaudeAiMcps') -eq 'true') {
        Add-SecuritySetting $State 'allowAllClaudeAiMcps' 'true' $Label 'REVIEW' 'All claude.ai connectors load alongside managed MCP config'
    }
    if ((Get-Scalar $json 'allowManagedMcpServersOnly') -eq 'true') {
        Add-SecuritySetting $State 'allowManagedMcpServersOnly' 'true' $Label 'INFO' 'Only managed MCP servers are respected'
    }

    # ---- Managed-only hardening switches ------------------------------------
    if ((Get-Scalar $json 'allowManagedHooksOnly') -eq 'true') {
        Add-SecuritySetting $State 'allowManagedHooksOnly' 'true' $Label 'INFO' 'Only managed hooks may run'
    }
    if ((Get-Scalar $json 'allowManagedPermissionRulesOnly') -eq 'true') {
        Add-SecuritySetting $State 'allowManagedPermissionRulesOnly' 'true' $Label 'INFO' 'Only managed permission rules apply'
    }
    $forceOrg = Get-Scalar $json 'forceLoginOrgUUID'
    if ($forceOrg) { Add-SecuritySetting $State 'forceLoginOrgUUID' $forceOrg $Label 'INFO' 'Login is restricted to a specific organization' }
    $minVersion = Get-Scalar $json 'requiredMinimumVersion'
    if ($minVersion) { Add-SecuritySetting $State 'requiredMinimumVersion' $minVersion $Label 'INFO' "Minimum required Claude Code version: $minVersion" }
    $maxVersion = Get-Scalar $json 'requiredMaximumVersion'
    if ($maxVersion) { Add-SecuritySetting $State 'requiredMaximumVersion' $maxVersion $Label 'INFO' "Maximum allowed Claude Code version: $maxVersion" }
    $managedMd = Get-Scalar $json 'claudeMd'
    if ($managedMd) {
        Add-SecuritySetting $State 'claudeMd' (Get-Truncated $managedMd 80) $Label 'INFO' 'Organization-managed CLAUDE.md instructions are injected'
    }

    # ---- Remote control / cross-session surface -----------------------------
    $crossInbound = Get-Scalar $json 'crossSessionInbound'
    if ($crossInbound -eq 'accept') {
        Add-SecuritySetting $State 'crossSessionInbound' 'accept' $Label 'REVIEW' 'Inbound cross-session messages are accepted automatically'
    } elseif ($crossInbound) {
        Add-SecuritySetting $State 'crossSessionInbound' $crossInbound $Label 'INFO' "Cross-session inbound policy: $crossInbound"
    }
    if ((Get-Scalar $json 'disableRemoteControl') -eq 'true') {
        Add-SecuritySetting $State 'disableRemoteControl' 'true' $Label 'INFO' 'Remote Control is disabled'
    }
    if ((Get-Scalar $json 'agentPushNotifEnabled') -eq 'true') {
        Add-SecuritySetting $State 'agentPushNotifEnabled' 'true' $Label 'INFO' 'Proactive push notifications via Remote Control are enabled'
    }
    $deepLink = Get-Scalar $json 'disableDeepLinkRegistration'
    if ($deepLink) {
        Add-SecuritySetting $State 'disableDeepLinkRegistration' $deepLink $Label 'INFO' 'claude-cli:// deep link registration policy'
    }

    # ---- Browser / simulator tool surface -----------------------------------
    $browserExternal = Get-Scalar $json 'browserExternalPageTools'
    if ($browserExternal) {
        Add-SecuritySetting $State 'browserExternalPageTools' $browserExternal $Label 'INFO' "Browser external-page tools policy: $browserExternal"
    }
    if ((Get-Scalar $json 'disableBrowserExternalNavigation') -eq 'true') {
        Add-SecuritySetting $State 'disableBrowserExternalNavigation' 'true' $Label 'INFO' 'External browsing in the Browser pane is blocked'
    }
    if ((Get-Scalar $json 'disableMobileSimulatorTools') -eq 'true') {
        Add-SecuritySetting $State 'disableMobileSimulatorTools' 'true' $Label 'INFO' 'Mobile simulator tools are blocked'
    }

    # ---- Auto-mode classifier ----------------------------------------------
    $autoAllow = Join-Values (Get-PropertyPath $json 'autoMode.allow')
    if ($autoAllow) { Add-SecuritySetting $State 'autoMode.allow' $autoAllow $Label 'REVIEW' 'Auto-mode allow rules are configured' }
    $autoDeny = Join-Values (Get-PropertyPath $json 'autoMode.hard_deny')
    if ($autoDeny) { Add-SecuritySetting $State 'autoMode.hard_deny' $autoDeny $Label 'INFO' 'Auto-mode hard-deny rules are configured' }
    if ((Get-Scalar $json 'autoMode.classifyAllShell') -eq 'true') {
        Add-SecuritySetting $State 'autoMode.classifyAllShell' 'true' $Label 'INFO' 'All shell commands are routed through the auto-mode classifier'
    }

    # ---- Data retention / memory -------------------------------------------
    $cleanupDays = Get-Scalar $json 'cleanupPeriodDays'
    if ($cleanupDays) {
        $days = 0
        [void][int]::TryParse($cleanupDays, [ref]$days)
        if ($days -gt 90) {
            Add-SecuritySetting $State 'cleanupPeriodDays' $cleanupDays $Label 'REVIEW' "Session data is retained for $cleanupDays days (default is 30)"
        } else {
            Add-SecuritySetting $State 'cleanupPeriodDays' $cleanupDays $Label 'INFO' "Session data retention: $cleanupDays days"
        }
    }
    if ((Get-Scalar $json 'autoMemoryEnabled') -eq 'false') {
        Add-SecuritySetting $State 'autoMemoryEnabled' 'false' $Label 'INFO' 'Auto memory is disabled'
    }
    $memoryDir = Get-Scalar $json 'autoMemoryDirectory'
    if ($memoryDir) {
        Add-SecuritySetting $State 'autoMemoryDirectory' $memoryDir $Label 'INFO' 'Custom auto-memory directory is configured'
    }

    # ---- Feature toggles and model policy ----------------------------------
    $model = Get-Scalar $json 'model'
    if ($model) { Add-Finding $State 'INFO' 'Config' "Model override in settings ($Label): $model" }
    $availableModels = Join-Values (Get-Property $json 'availableModels')
    if ($availableModels) { Add-SecuritySetting $State 'availableModels' $availableModels $Label 'INFO' 'Model choices are restricted' }
    if ((Get-Scalar $json 'enforceAvailableModels') -eq 'true') {
        Add-SecuritySetting $State 'enforceAvailableModels' 'true' $Label 'INFO' 'Model restriction is enforced'
    }
    $mainAgent = Get-Scalar $json 'agent'
    if ($mainAgent) {
        Add-SecuritySetting $State 'agent' $mainAgent $Label 'REVIEW' 'A custom agent runs as the main thread (overrides default system prompt and tools)'
    }
    $outputStyle = Get-Scalar $json 'outputStyle'
    if ($outputStyle) { Add-SecuritySetting $State 'outputStyle' $outputStyle $Label 'INFO' "Output style: $outputStyle" }
    $defaultShell = Get-Scalar $json 'defaultShell'
    if ($defaultShell) { Add-SecuritySetting $State 'defaultShell' $defaultShell $Label 'INFO' "Default shell: $defaultShell" }
    if ((Get-Scalar $json 'disableBundledSkills') -eq 'true') {
        Add-SecuritySetting $State 'disableBundledSkills' 'true' $Label 'INFO' 'Bundled skills and workflows are disabled'
    }
    if ((Get-Scalar $json 'disableArtifact') -eq 'true') {
        Add-SecuritySetting $State 'disableArtifact' 'true' $Label 'INFO' 'Artifact publishing is disabled'
    }
    if ((Get-Scalar $json 'disableAgentView') -eq 'true') {
        Add-SecuritySetting $State 'disableAgentView' 'true' $Label 'INFO' 'Background agents and agent view are disabled'
    }
}

function Collect-MainConfig($State) {
    $path = Join-Path $State.Home '.claude.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Add-Finding $State 'INFO' 'Config' '.claude.json not found' $path
        return
    }
    Add-SensitiveFile $State '.claude.json' $path 'REVIEW'
    $json = Read-JsonFile $path
    if ($null -eq $json) {
        Add-Finding $State 'REVIEW' 'Config' 'Unable to parse .claude.json' $path
        return
    }
    $model = Get-Scalar $json 'model'
    if ($model) { Add-Finding $State 'INFO' 'Config' "Default model: $model" }
    $userId = Get-Scalar $json 'userID'
    if ($userId) {
        Add-Finding $State 'INFO' 'Config' 'User ID present' "$(Get-Truncated $userId 16)..."
    }

    foreach ($project in (Get-ObjectEntries (Get-Property $json 'projects'))) {
        $value = $project.Value
        $projectName = [IO.Path]::GetFileName($project.Name.TrimEnd('\', '/'))
        $trusted = (Get-Property $value 'hasTrustDialogAccepted') -eq $true
        $allowedList = @(Get-Property $value 'allowedTools')
        $allowed = Join-Values (Get-Property $value 'allowedTools')
        $enabled = Join-Values (Get-Property $value 'enabledMcpjsonServers')
        $disabled = Join-Values (Get-Property $value 'disabledMcpjsonServers')
        $localMcpObject = Get-Property $value 'mcpServers'
        $localMcp = Get-KeyNames $localMcpObject
        $externalIncludes = (Get-Property $value 'hasClaudeMdExternalIncludesApproved') -eq $true
        $contextUris = Join-Values (Get-Property $value 'mcpContextUris')
        $State.Projects.Add([pscustomobject]@{
            path = $project.Name
            detail = "trust=$($trusted.ToString().ToLowerInvariant()) | tools=$(if ($allowed) {$allowed} else {'none'}) | mcp_enabled=$(if ($enabled) {$enabled} else {'none'}) | mcp_disabled=$(if ($disabled) {$disabled} else {'none'}) | mcp_local=$(if ($localMcp) {$localMcp} else {'none'}) | external_includes=$($externalIncludes.ToString().ToLowerInvariant())"
        })
        if ($trusted) { Add-Finding $State 'WARN' 'Projects' 'Trusted project grants Claude Code broader workspace autonomy' $project.Name }
        # Locally-scoped MCP servers live in .claude.json rather than .mcp.json.
        if ($localMcp) {
            Add-Finding $State 'REVIEW' 'MCP Servers' "Project-local MCP servers defined in .claude.json: $projectName" $localMcp
            Add-McpServersFromObject $State $localMcpObject "project-local:$projectName"
        }
        # External includes in CLAUDE.md pull instructions from outside the repo.
        if ($externalIncludes) {
            Add-Finding $State 'REVIEW' 'Projects' "CLAUDE.md external includes approved for $projectName" `
                'instructions may be loaded from outside the workspace'
        }
        if ($contextUris) { Add-Finding $State 'INFO' 'Projects' "MCP context URIs configured: $projectName" $contextUris }
        if ($allowed) {
            Add-Finding $State 'REVIEW' 'Projects' "Project has pre-approved tools: $projectName" (Get-ListSummary $allowed $allowedList.Count)
        }
        if ($enabled) {
            Add-Finding $State 'INFO' 'Projects' "Project has enabled MCP .json servers: $projectName" $enabled
        }
        if (Test-Path -LiteralPath $project.Name -PathType Container) {
            Collect-SettingsFile $State (Join-Path $project.Name '.claude\settings.json') "project:$projectName"
            Collect-SettingsFile $State (Join-Path $project.Name '.claude\settings.local.json') "project-local:$projectName"
            Add-McpServersFromJson $State (Join-Path $project.Name '.mcp.json') "project-mcp:$projectName"
        }
    }
    if ($State.Projects.Count -gt 0) { Add-Finding $State 'INFO' 'Projects' "$($State.Projects.Count) project(s) in config" }

    foreach ($entry in (Get-ObjectEntries (Get-Property $json 'bypassPermissionsGateByAccount'))) {
        if ($entry.Value -eq $true) {
            Add-Finding $State 'WARN' 'Permissions' 'Bypass permissions gate is ENABLED for account' $entry.Name
        }
    }

    # ---- Plugin / skill usage history --------------------------------------
    $pluginUsage = @(Get-ObjectEntries (Get-Property $json 'pluginUsage'))
    if ($pluginUsage.Count -gt 0) {
        Add-Finding $State 'INFO' 'Plugins' "$($pluginUsage.Count) plugin package(s) in usage history" (($pluginUsage | ForEach-Object Name) -join ', ')
        foreach ($used in $pluginUsage) {
            $marketplace = ''
            if ($used.Name -like '*@*') { $marketplace = $used.Name.Substring($used.Name.LastIndexOf('@') + 1) }
            $State.Plugins.Add([pscustomobject]@{
                name = $used.Name
                state = 'used'
                scope = 'usage-history'
                provenance = Get-PluginProvenance $marketplace
                components = '(history only)'
                version = 'unknown'
                author = 'unknown'
                path = ''
            })
        }
    }
    $skillUsage = @(Get-ObjectEntries (Get-Property $json 'skillUsage'))
    if ($skillUsage.Count -gt 0) {
        Add-Finding $State 'INFO' 'Skills' "$($skillUsage.Count) skill(s) in usage history" (($skillUsage | ForEach-Object Name) -join ', ')
    }

    # ---- Account / device identity -----------------------------------------
    $orgName = Get-Scalar $json 'oauthAccount.organizationName'
    $seatTier = Get-Scalar $json 'oauthAccount.seatTier'
    $billing = Get-Scalar $json 'oauthAccount.billingType'
    $email = Get-Scalar $json 'oauthAccount.emailAddress'
    $machineId = Get-Scalar $json 'machineID'
    if ($orgName) {
        # Personal orgs are named after the account email; mask it like the address itself.
        $orgDisplay = if ($orgName -match '@.+\.') { '[personal organization]' } else { $orgName }
        Add-Finding $State 'INFO' 'Account' "Signed in to organization: $orgDisplay" `
            "seat=$(if ($seatTier) {$seatTier} else {'unknown'}); billing=$(if ($billing) {$billing} else {'unknown'})"
    }
    # Report only the domain: reports are shared, the mailbox is not needed.
    if ($email) { Add-Finding $State 'INFO' 'Account' 'Account email present' "domain=$($email.Substring($email.LastIndexOf('@') + 1))" }
    if ($machineId) { Add-Finding $State 'INFO' 'Account' 'Machine ID present' "$(Get-Truncated $machineId 16)..." }
}

# Enterprise policy settings outrank every user setting, so their presence (or
# absence) is a material fact about the machine. On Windows they arrive either as
# JSON under Program Files or as registry policy values.
function Collect-ManagedSettings($State) {
    $found = $false
    if (Test-Path -LiteralPath $script:ManagedSettingsFile -PathType Leaf) {
        $found = $true
        Add-SensitiveFile $State 'managed-settings.json' $script:ManagedSettingsFile
        Add-Finding $State 'INFO' 'Managed Policy' 'Enterprise managed settings are in effect' $script:ManagedSettingsFile
        Collect-SettingsFile $State $script:ManagedSettingsFile 'managed'
    }
    foreach ($file in (Get-MatchingFiles (Join-Path $script:ManagedSettingsDir '*.json'))) {
        $found = $true
        Add-Finding $State 'INFO' 'Managed Policy' "Managed settings drop-in: $($file.Name)" $file.FullName
        Collect-SettingsFile $State $file.FullName "managed-dropin:$($file.Name)"
    }
    foreach ($key in $script:ManagedRegistryKeys) {
        if (-not (Test-Path -LiteralPath $key)) { continue }
        $found = $true
        Add-Finding $State 'INFO' 'Managed Policy' 'Registry policy key is present' $key
        $properties = $null
        try { $properties = Get-ItemProperty -LiteralPath $key -ErrorAction Stop } catch { }
        if ($null -eq $properties) { continue }
        foreach ($property in $properties.PSObject.Properties) {
            if ($property.Name -like 'PS*') { continue }
            $value = Get-RedactedValue $property.Name $property.Value
            Add-SecuritySetting $State $property.Name (Get-Truncated $value 200) "managed-registry:$key" 'INFO' `
                "Managed policy value set in the registry: $($property.Name)"
        }
    }
    if (-not $found) {
        Add-Finding $State 'INFO' 'Managed Policy' 'No enterprise managed settings found' `
            'unmanaged installation; user settings are authoritative'
    }
}

# Report which auto-executing components a plugin ships. Plugins are arbitrary
# third-party code, so the component list is the interesting part.
function Get-PluginComponents([string]$Root) {
    $parts = [Collections.Generic.List[string]]::new()
    if ((Test-Path -LiteralPath (Join-Path $Root 'hooks\hooks.json') -PathType Leaf) -or
        (Test-Path -LiteralPath (Join-Path $Root 'hooks.json') -PathType Leaf)) { $parts.Add('hooks') }
    if (Test-Path -LiteralPath (Join-Path $Root '.mcp.json') -PathType Leaf) { $parts.Add('mcp') }
    if (Test-Path -LiteralPath (Join-Path $Root '.lsp.json') -PathType Leaf) { $parts.Add('lsp') }
    if ((Test-Path -LiteralPath (Join-Path $Root 'monitors\monitors.json') -PathType Leaf) -or
        (Test-Path -LiteralPath (Join-Path $Root 'monitors.json') -PathType Leaf)) { $parts.Add('monitors') }
    if (Test-Path -LiteralPath (Join-Path $Root 'bin') -PathType Container) { $parts.Add('bin') }
    if (Test-Path -LiteralPath (Join-Path $Root 'agents') -PathType Container) { $parts.Add('agents') }
    if (Test-Path -LiteralPath (Join-Path $Root 'skills') -PathType Container) { $parts.Add('skills') }
    if (Test-Path -LiteralPath (Join-Path $Root 'commands') -PathType Container) { $parts.Add('commands') }
    if (Test-Path -LiteralPath (Join-Path $Root 'settings.json') -PathType Leaf) { $parts.Add('settings') }
    $parts -join ','
}

# Background monitors run unsandboxed shell commands for the whole session.
function Collect-MonitorsFrom($State, [string]$Root, [string]$PluginName) {
    $file = Join-Path $Root 'monitors\monitors.json'
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { $file = Join-Path $Root 'monitors.json' }
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { return }
    $json = Read-JsonFile $file
    if ($null -eq $json) { return }
    $monitors = if ($json -is [array]) { $json } else { @(Get-Property $json 'monitors') }
    foreach ($monitor in $monitors) {
        if ($null -eq $monitor) { continue }
        $name = [string](Get-Property $monitor 'name')
        if (-not $name) { $name = 'unnamed' }
        $command = [string](Get-Property $monitor 'command')
        $when = [string](Get-Property $monitor 'when')
        if (-not $when) { $when = 'always' }
        $description = [string](Get-Property $monitor 'description')
        $State.Monitors.Add([pscustomobject]@{
            name = $name
            plugin = $PluginName
            when = $when
            command = $command
            description = $description
        })
        Add-Finding $State 'WARN' 'Monitors' "Plugin runs a background monitor command: $PluginName/$name" `
            "when=$when; cmd=$(Get-Truncated $command 100)"
    }
}

# Inspect one plugin root: manifest metadata, executable surface, nested MCP/hooks.
function Add-Plugin($State, [string]$Root, [string]$Marketplace, [string]$Scope) {
    if (-not $State.SeenPlugin.Add($Root)) { return }
    $manifest = Join-Path $Root '.claude-plugin\plugin.json'
    $name = ''
    $version = ''
    $author = ''
    if (Test-Path -LiteralPath $manifest -PathType Leaf) {
        $json = Read-JsonFile $manifest
        $name = Get-Scalar $json 'name'
        $version = Get-Scalar $json 'version'
        $authorValue = Get-Property $json 'author'
        if ($authorValue -is [string]) {
            $author = $authorValue
        } elseif ($null -ne $authorValue) {
            foreach ($field in @('name', 'email', 'url')) {
                if (-not $author) { $author = [string](Get-Property $authorValue $field) }
            }
        }
    }
    if (-not $name) { $name = Split-Path -Leaf $Root }
    $provenance = Get-PluginProvenance $Marketplace
    $components = Get-PluginComponents $Root
    $State.Plugins.Add([pscustomobject]@{
        name = "$name@$(if ($Marketplace) {$Marketplace} else {'unknown'})"
        state = 'installed'
        scope = $Scope
        provenance = $provenance
        components = $(if ($components) { $components } else { 'none' })
        version = $(if ($version) { $version } else { 'unknown' })
        author = $(if ($author) { $author } else { 'unknown' })
        path = $Root
    })
    if ($provenance -in @('third-party', 'unknown')) {
        Add-Finding $State 'WARN' 'Plugins' "Installed plugin from a non-Anthropic source: $name" `
            "marketplace=$(if ($Marketplace) {$Marketplace} else {'unknown'}); provenance=$provenance; components=$(if ($components) {$components} else {'none'})"
    } else {
        Add-Finding $State 'INFO' 'Plugins' "Installed plugin: $name" `
            "marketplace=$(if ($Marketplace) {$Marketplace} else {'unknown'}); version=$(if ($version) {$version} else {'unknown'}); components=$(if ($components) {$components} else {'none'})"
    }

    # bin/ is prepended to PATH for Bash tool calls while the plugin is enabled.
    $bin = Join-Path $Root 'bin'
    if (Test-Path -LiteralPath $bin -PathType Container) {
        $executables = (@(Get-ChildItem -LiteralPath $bin -File -Force -ErrorAction SilentlyContinue) | ForEach-Object Name) -join ', '
        Add-Finding $State 'WARN' 'Plugins' "Plugin adds executables to the Bash PATH: $name" "bin=$(if ($executables) {$executables} else {'none'})"
    }
    if (Test-Path -LiteralPath (Join-Path $Root '.lsp.json') -PathType Leaf) {
        Add-Finding $State 'REVIEW' 'Plugins' "Plugin starts language server processes: $name" (Join-Path $Root '.lsp.json')
    }

    # Nested components carry their own execution surface.
    Add-McpServersFromJson $State (Join-Path $Root '.mcp.json') "plugin:$name"
    Add-HooksFromJson $State (Join-Path $Root 'hooks\hooks.json') "plugin:$name"
    Add-HooksFromJson $State (Join-Path $Root 'hooks.json') "plugin:$name"
    Collect-MonitorsFrom $State $Root $name
}

function Collect-Plugins($State) {
    # Marketplace plugins: <claude-dir>\plugins\cache\{marketplace}\{plugin}\{version}\
    $cacheRoot = Join-Path $State.ClaudeDir 'plugins\cache'
    foreach ($versionDir in (Get-MatchingDirectories (Join-Path $cacheRoot '*\*\*'))) {
        $root = $versionDir.FullName
        $marketplace = Split-Path -Leaf (Split-Path -Parent (Split-Path -Parent $root))
        if (Test-Path -LiteralPath (Join-Path $root '.claude-plugin\plugin.json') -PathType Leaf) {
            Add-Plugin $State $root $marketplace 'user-cache'
        } elseif (Get-PluginComponents $root) {
            # Plugins without a manifest still load via auto-discovery.
            Add-Plugin $State $root $marketplace 'user-cache'
        }
    }

    # Skills-directory plugins auto-load with no marketplace or install step.
    foreach ($dir in (Get-MatchingDirectories (Join-Path $State.ClaudeDir 'skills\*'))) {
        if (Test-Path -LiteralPath (Join-Path $dir.FullName '.claude-plugin\plugin.json') -PathType Leaf) {
            Add-Plugin $State $dir.FullName 'skills-dir' 'user-skills-dir'
        }
    }

    $dataDir = Join-Path $State.ClaudeDir 'plugins\data'
    if (Test-Path -LiteralPath $dataDir -PathType Container) {
        $count = @(Get-ChildItem -LiteralPath $dataDir -Directory -Force -ErrorAction SilentlyContinue).Count
        if ($count -gt 0) { Add-Finding $State 'INFO' 'Plugins' "Persistent plugin data directories: $count" $dataDir }
    }
    if ($State.Plugins.Count -gt 0) { Add-Finding $State 'INFO' 'Plugins' "$($State.Plugins.Count) plugin record(s) found" }
}

# Parse name/description/tools/model out of a SKILL.md (or agent .md) frontmatter block.
function Get-SkillFrontmatter([string]$Path) {
    $result = [pscustomobject]@{
        Name = Split-Path -Leaf (Split-Path -Parent $Path)
        Description = ''
        Tools = ''
        Model = ''
    }
    $lines = $null
    try { $lines = @(Get-Content -LiteralPath $Path -TotalCount 60 -ErrorAction Stop) } catch { return $result }
    if ($lines.Count -eq 0 -or $lines[0].Trim() -ne '---') { return $result }
    $inDescription = $false
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line.Trim() -eq '---') { break }
        if ($line -match '^name:\s*(.*)$') {
            $result.Name = $Matches[1].Trim().Trim('"').Trim("'")
            $inDescription = $false
        } elseif ($line -match '^description:\s*(.*)$') {
            $value = $Matches[1].Trim().Trim('"').Trim("'")
            if ($value -in @('>', '|')) { $value = '' }
            $result.Description = $value
            $inDescription = $true
        } elseif ($line -match '^(allowed-tools|tools):\s*(.*)$') {
            $result.Tools = $Matches[2].Trim().Trim('"').Trim("'")
            $inDescription = $false
        } elseif ($line -match '^model:\s*(.*)$') {
            $result.Model = $Matches[1].Trim().Trim('"').Trim("'")
            $inDescription = $false
        } elseif ($inDescription -and $line -match '^\s+\S') {
            $result.Description = "$($result.Description) $($line.Trim())".Trim()
        } else {
            $inDescription = $false
        }
    }
    # Keep descriptions short: they are inventory labels, not documentation.
    $result.Description = Get-Truncated $result.Description 200
    if (-not $result.Name) { $result.Name = Split-Path -Leaf (Split-Path -Parent $Path) }
    $result
}

function Add-SkillEntry($State, [string]$Path, [string]$Kind, [string]$Source) {
    $meta = Get-SkillFrontmatter $Path
    $State.Skills.Add([pscustomobject]@{
        name = $meta.Name
        kind = $Kind
        source = $Source
        description = $meta.Description
        tools = $(if ($meta.Tools) { $meta.Tools } else { 'default' })
        path = $Path
    })
    if ($meta.Tools) {
        Add-Finding $State 'INFO' 'Skills' "$Kind declares explicit tool access: $($meta.Name)" "tools=$($meta.Tools); source=$Source"
    }
}

# Skills, agents and commands are model-invocable instructions; inventory them so
# drift shows up in diffs.
function Collect-Skills($State) {
    $claudeDir = $State.ClaudeDir
    $skillPatterns = @(
        (Join-Path $claudeDir 'skills\*\SKILL.md'),
        (Join-Path $claudeDir 'skills\*\skills\*\SKILL.md')
    )
    foreach ($pattern in $skillPatterns) {
        foreach ($file in (Get-MatchingFiles $pattern)) { Add-SkillEntry $State $file.FullName 'skill' 'user' }
    }
    foreach ($pattern in @(
        (Join-Path $claudeDir 'plugins\cache\*\*\*\skills\*\SKILL.md'),
        (Join-Path $claudeDir 'plugins\cache\*\*\*\SKILL.md')
    )) {
        foreach ($file in (Get-MatchingFiles $pattern)) { Add-SkillEntry $State $file.FullName 'skill' 'plugin' }
    }
    foreach ($pattern in @(
        (Join-Path $claudeDir 'agents\*.md'),
        (Join-Path $claudeDir 'plugins\cache\*\*\*\agents\*.md')
    )) {
        foreach ($file in (Get-MatchingFiles $pattern)) { Add-SkillEntry $State $file.FullName 'agent' 'user' }
    }
    $commandsDir = Join-Path $claudeDir 'commands'
    if (Test-Path -LiteralPath $commandsDir -PathType Container) {
        foreach ($file in @(Get-ChildItem -LiteralPath $commandsDir -Filter '*.md' -File -Recurse -Force -ErrorAction SilentlyContinue)) {
            Add-SkillEntry $State $file.FullName 'command' 'user'
        }
    }

    # Project scope loads only after the workspace trust dialog is accepted.
    $configPath = Join-Path $State.Home '.claude.json'
    if (Test-Path -LiteralPath $configPath -PathType Leaf) {
        $json = Read-JsonFile $configPath
        foreach ($project in (Get-ObjectEntries (Get-Property $json 'projects'))) {
            $projectPath = $project.Name
            if (-not (Test-Path -LiteralPath $projectPath -PathType Container)) { continue }
            $projectName = [IO.Path]::GetFileName($projectPath.TrimEnd('\', '/'))
            foreach ($file in (Get-MatchingFiles (Join-Path $projectPath '.claude\skills\*\SKILL.md'))) {
                Add-SkillEntry $State $file.FullName 'skill' "project:$projectName"
            }
            foreach ($file in (Get-MatchingFiles (Join-Path $projectPath '.claude\agents\*.md'))) {
                Add-SkillEntry $State $file.FullName 'agent' "project:$projectName"
            }
            foreach ($dir in (Get-MatchingDirectories (Join-Path $projectPath '.claude\skills\*'))) {
                if (Test-Path -LiteralPath (Join-Path $dir.FullName '.claude-plugin\plugin.json') -PathType Leaf) {
                    Add-Plugin $State $dir.FullName 'skills-dir' "project:$projectName"
                }
            }
        }
    }
    if ($State.Skills.Count -gt 0) {
        Add-Finding $State 'INFO' 'Skills' "$($State.Skills.Count) skill/agent/command definition(s) found"
    }
}

function Get-DesktopRoots($State) {
    $roots = [Collections.Generic.List[string]]::new()
    if ($State.User -eq [Environment]::UserName) {
        if ($env:APPDATA) { $roots.Add((Join-Path $env:APPDATA 'Claude')) }
        if ($env:LOCALAPPDATA) { $roots.Add((Join-Path $env:LOCALAPPDATA 'Claude')) }
    } else {
        $roots.Add((Join-Path $State.Home 'AppData\Roaming\Claude'))
        $roots.Add((Join-Path $State.Home 'AppData\Local\Claude'))
    }
    @($roots | Select-Object -Unique)
}

function Add-RetentionDirectory($State, [string]$Name, [string]$Path, [long]$SizeLimit = 100MB) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }
    $stats = Get-DirectoryStats $Path
    $State.Retention.Add([pscustomobject]@{
        name = $Name
        file_count = [string]$stats.Count
        bytes = [string]$stats.Bytes
        latest_mtime = $stats.Latest
        path = $Path
    })
    Add-Finding $State 'INFO' 'Retention' "$Name contains $($stats.Count) file(s)" "size=$(Format-Bytes $stats.Bytes); latest=$(if ($stats.Latest) {$stats.Latest} else {'none'})"
    if ($stats.Bytes -gt $SizeLimit) {
        Add-Finding $State 'REVIEW' 'Retention' "$Name retained data is larger than $(Format-Bytes $SizeLimit)" (Format-Bytes $stats.Bytes)
    }
    if ($stats.Count -gt 1000) {
        Add-Finding $State 'REVIEW' 'Retention' "$Name contains more than 1000 files" "$($stats.Count) files"
    }
}

function Collect-Desktop($State) {
    foreach ($root in (Get-DesktopRoots $State)) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        $desktopConfig = Join-Path $root 'claude_desktop_config.json'
        if (Test-Path -LiteralPath $desktopConfig -PathType Leaf) {
            Add-SensitiveFile $State 'claude_desktop_config.json' $desktopConfig 'REVIEW'
            Add-McpServersFromJson $State $desktopConfig 'desktop'
            $json = Read-JsonFile $desktopConfig
            $preferences = Get-Property $json 'preferences'
            foreach ($entry in (Get-ObjectEntries (Get-Property $preferences 'bypassPermissionsGateByAccount'))) {
                if ($entry.Value -eq $true) {
                    Add-Finding $State 'WARN' 'Permissions' 'Desktop: bypass permissions gate ENABLED for account' $entry.Name
                }
            }
            $web = (Get-Property $preferences 'coworkWebSearchEnabled') -eq $true
            Add-Finding $State 'INFO' 'Desktop' "Cowork web search enabled: $($web.ToString().ToLowerInvariant())"
            if ((Get-Property $preferences 'coworkScheduledTasksEnabled') -eq $true) {
                Add-Finding $State 'REVIEW' 'Desktop' 'Cowork scheduled tasks are enabled'
            }
            if ((Get-Property $preferences 'coworkHipaaRestricted') -eq $true) {
                Add-Finding $State 'INFO' 'Desktop' 'HIPAA-restricted mode is active'
            }
            $coworkPath = [string](Get-Property $json 'coworkUserFilesPath')
            if ($coworkPath) {
                Add-Finding $State 'INFO' 'Desktop' 'Cowork user files path' $coworkPath
                Add-RetentionDirectory $State 'cowork-user-files' $coworkPath 500MB
            }
        }
        Add-SensitiveFile $State 'config.json' (Join-Path $root 'config.json') 'WARN'
        $buddy = Join-Path $root 'buddy-tokens.json'
        if (Test-Path -LiteralPath $buddy -PathType Leaf) {
            Add-SensitiveFile $State 'buddy-tokens.json' $buddy 'WARN'
            Add-Finding $State 'REVIEW' 'Sensitive Files' 'buddy-tokens.json present (may contain auth tokens)'
        }
        Add-SensitiveFile $State 'ant-did' (Join-Path $root 'ant-did')
        Add-RetentionDirectory $State 'claude-code-sessions' (Join-Path $root 'claude-code-sessions')
        Add-RetentionDirectory $State 'local-agent-mode-sessions' (Join-Path $root 'local-agent-mode-sessions')
    }
}

function Collect-SensitiveFiles($State) {
    $claudeDir = $State.ClaudeDir

    # Session peer tokens: <claude-dir>\sessions\<pid>.<hash>.key holds a live
    # credential used to attach to a running session.
    $keyFiles = Get-MatchingFiles (Join-Path $claudeDir 'sessions\*.key')
    foreach ($file in $keyFiles) {
        Add-SensitiveFile $State "sessions\$($file.Name)" $file.FullName 'WARN'
    }
    if ($keyFiles.Count -gt 0) {
        Add-Finding $State 'INFO' 'Sensitive Files' "$($keyFiles.Count) session peer-token key file(s) present" (Join-Path $claudeDir 'sessions')
    }

    # OAuth credentials: a file on Windows/WSL installs.
    $credentials = Join-Path $claudeDir '.credentials.json'
    if (Test-Path -LiteralPath $credentials -PathType Leaf) {
        Add-SensitiveFile $State '.credentials.json' $credentials 'WARN'
        Add-Finding $State 'REVIEW' 'Sensitive Files' 'OAuth credentials file present' $credentials
    }

    # Telemetry spool: undelivered events queued on disk.
    $telemetry = Join-Path $claudeDir 'telemetry'
    if (Test-Path -LiteralPath $telemetry -PathType Container) {
        $stats = Get-DirectoryStats $telemetry
        if ($stats.Count -gt 0) {
            Add-Finding $State 'REVIEW' 'Local Data' 'Undelivered telemetry events are spooled on disk' `
                "$($stats.Count) file(s); size=$(Format-Bytes $stats.Bytes); $telemetry"
        }
    }

    $backups = Join-Path $claudeDir 'backups'
    if (Test-Path -LiteralPath $backups -PathType Container) {
        $stats = Get-DirectoryStats $backups
        Add-Finding $State 'INFO' 'Sensitive Files' "backups directory contains $($stats.Count) file(s)" "size=$(Format-Bytes $stats.Bytes)"
    }
}

function Collect-Retention($State) {
    foreach ($name in @(
        'sessions', 'shell-snapshots', 'session-env', 'projects', 'tasks', 'telemetry',
        'todos', 'history', 'file-history', 'plugins\cache', 'plugins\data'
    )) {
        Add-RetentionDirectory $State $name (Join-Path $State.ClaudeDir $name)
    }
}

function Collect-Runtime($State) {
    # Installed version: the audit rules track a specific Claude Code generation,
    # so record which one this machine is actually running.
    $versions = [Collections.Generic.List[string]]::new()
    foreach ($root in (Get-DesktopRoots $State)) {
        foreach ($dir in (Get-MatchingDirectories (Join-Path $root 'claude-code\*'))) {
            if (-not $versions.Contains($dir.Name)) { $versions.Add($dir.Name) }
        }
    }
    if ($versions.Count -gt 0) {
        Add-Finding $State 'INFO' 'Runtime' "Claude Code version(s) installed: $($versions -join ', ')"
    } elseif (Get-Command claude -ErrorAction SilentlyContinue) {
        $version = ''
        try { $version = (& claude --version 2>$null | Select-Object -First 1) } catch { }
        if ($version) { Add-Finding $State 'INFO' 'Runtime' "Claude Code version: $version" }
    }

    # Background task records written by the Task/agent system.
    $tasksDir = Join-Path $State.ClaudeDir 'tasks'
    if (Test-Path -LiteralPath $tasksDir -PathType Container) {
        $count = @(Get-ChildItem -LiteralPath $tasksDir -Directory -Force -ErrorAction SilentlyContinue).Count
        if ($count -gt 0) { Add-Finding $State 'INFO' 'Runtime' "Background task record(s) on disk: $count" $tasksDir }
    }

    $sessionsDir = Join-Path $State.ClaudeDir 'sessions'
    if (Test-Path -LiteralPath $sessionsDir -PathType Container) {
        foreach ($file in @(Get-ChildItem -LiteralPath $sessionsDir -Filter '*.json' -File -ErrorAction SilentlyContinue)) {
            $session = Read-JsonFile $file.FullName
            if ($null -eq $session) { continue }
            $pidValue = [string](Get-Property $session 'pid')
            $cwd = [string](Get-Property $session 'cwd')
            $version = [string](Get-Property $session 'version')
            $kind = [string](Get-Property $session 'kind')
            $State.ActiveSessions.Add([pscustomobject]@{
                pid = if ($pidValue) { $pidValue } else { '?' }
                kind = if ($kind) { $kind } else { 'unknown' }
                version = if ($version) { $version } else { '?' }
                cwd = if ($cwd) { $cwd } else { '?' }
            })
            $running = $false
            if ($pidValue -match '^\d+$') {
                $running = $null -ne (Get-Process -Id ([int]$pidValue) -ErrorAction SilentlyContinue)
            }
            if ($running) {
                Add-Finding $State 'INFO' 'Runtime' "Active Claude Code session (pid $pidValue)" "kind=$kind; version=$version; cwd=$cwd"
            } else {
                Add-Finding $State 'INFO' 'Runtime' "Stale session record (pid $(if ($pidValue) {$pidValue} else {'?'}) not running)" $file.Name
            }
        }
    }

    $processes = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.ProcessName -match '(?i)(claude|anthropic)'
    })
    if ($processes.Count -gt 0) {
        Add-Finding $State 'INFO' 'Runtime' "Claude-related process(es) running: $($processes.Count)"
    }
    # Get-ScheduledTask can block for minutes on some machines, so it runs in a
    # child job with a bounded wait rather than stalling the whole audit.
    $taskJob = $null
    try {
        $taskJob = Start-Job -ScriptBlock {
            Get-ScheduledTask -ErrorAction Stop | Where-Object {
                $_.TaskName -match '(?i)(claude|anthropic)' -or
                ($_.Actions | Out-String) -match '(?i)(claude|anthropic)'
            } | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" }
        }
        if (Wait-Job -Job $taskJob -Timeout 30) {
            foreach ($task in @(Receive-Job -Job $taskJob -ErrorAction SilentlyContinue)) {
                Add-Finding $State 'WARN' 'Runtime' 'Claude-related scheduled task found' $task
            }
        } else {
            Add-Finding $State 'INFO' 'Runtime' 'Scheduled tasks could not be inspected' 'Get-ScheduledTask did not respond within 30s'
        }
    } catch {
        Add-Finding $State 'INFO' 'Runtime' 'Scheduled tasks could not be inspected' $_.Exception.Message
    } finally {
        if ($taskJob) { Remove-Job -Job $taskJob -Force -ErrorAction SilentlyContinue }
    }
    foreach ($hive in @('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run')) {
        if (-not (Test-Path -LiteralPath $hive)) { continue }
        $properties = $null
        try { $properties = Get-ItemProperty -LiteralPath $hive -ErrorAction Stop } catch { continue }
        foreach ($property in $properties.PSObject.Properties) {
            if ($property.Name -like 'PS*') { continue }
            if ("$($property.Name) $($property.Value)" -match '(?i)(claude|anthropic)') {
                Add-Finding $State 'WARN' 'Runtime' 'Claude-related autorun entry found' "$hive\$($property.Name) = $($property.Value)"
            }
        }
    }
}

# Checks that only make sense once every source has been parsed.
function Invoke-CrossChecks($State) {
    $httpHooks = @($State.Hooks | Where-Object type -eq 'http').Count
    $hasAllowlist = @($State.SecuritySettings | Where-Object key -eq 'allowedHttpHookUrls').Count -gt 0
    if ($httpHooks -gt 0 -and -not $hasAllowlist) {
        Add-Finding $State 'WARN' 'Hooks' 'HTTP hooks are configured with no URL allowlist' `
            "$httpHooks HTTP hook(s); set allowedHttpHookUrls to restrict where session data can be posted"
    }
}

function Invoke-Audit([string]$UserName, [string]$HomeDir) {
    $claudeDir = if ($script:Options.ClaudeDir) {
        (Resolve-Path -LiteralPath $script:Options.ClaudeDir).Path
    } else {
        Join-Path $HomeDir '.claude'
    }
    if ($script:Options.ClaudeDir) { $HomeDir = Split-Path -Parent $claudeDir }
    $state = New-AuditState $UserName $HomeDir $claudeDir
    if (-not (Test-Path -LiteralPath $claudeDir -PathType Container) -and
        -not (Test-Path -LiteralPath (Join-Path $HomeDir '.claude.json') -PathType Leaf)) {
        Add-Finding $state 'INFO' 'General' 'Claude Code data not found' $claudeDir
        Collect-ManagedSettings $state
        Collect-Desktop $state
        Collect-Runtime $state
        return $state
    }
    Collect-MainConfig $state
    Collect-ManagedSettings $state
    $globalSettings = Join-Path $claudeDir 'settings.json'
    if (Test-Path -LiteralPath $globalSettings -PathType Leaf) {
        Add-SensitiveFile $state 'settings.json (global)' $globalSettings 'REVIEW'
        Collect-SettingsFile $state $globalSettings 'global'
    }
    $localSettings = Join-Path $claudeDir 'settings.local.json'
    if (Test-Path -LiteralPath $localSettings -PathType Leaf) {
        Add-SensitiveFile $state 'settings.local.json' $localSettings 'REVIEW'
        Collect-SettingsFile $state $localSettings 'global-local'
    }
    Collect-Plugins $state
    Collect-Skills $state
    Collect-Desktop $state
    Collect-SensitiveFiles $state
    Collect-Retention $state
    Collect-Runtime $state
    Invoke-CrossChecks $state
    $state
}

# Section table layout shared by the JSON, terminal, and HTML renderers.
$script:ReportSections = @(
    @{ Title = 'MCP Servers'; Key = 'McpServers'; Json = 'mcp_servers'; First = 'name' },
    @{ Title = 'Projects'; Key = 'Projects'; Json = 'projects'; First = 'path' },
    @{ Title = 'Hooks'; Key = 'Hooks'; Json = 'hooks'; First = 'event' },
    @{ Title = 'Plugins'; Key = 'Plugins'; Json = 'plugins'; First = 'name' },
    @{ Title = 'Skills / Agents'; Key = 'Skills'; Json = 'skills'; First = 'name' },
    @{ Title = 'Background Monitors'; Key = 'Monitors'; Json = 'monitors'; First = 'name' },
    @{ Title = 'Security Settings'; Key = 'SecuritySettings'; Json = 'security_settings'; First = 'key' },
    @{ Title = 'Active Sessions'; Key = 'ActiveSessions'; Json = 'active_sessions'; First = 'pid' },
    @{ Title = 'Sensitive Files'; Key = 'SensitiveFiles'; Json = 'sensitive_files'; First = 'name' },
    @{ Title = 'Retention'; Key = 'Retention'; Json = 'retention'; First = 'name' }
)

function Convert-StateForOutput($State, [switch]$SummaryOnly) {
    $summary = Get-Summary $State
    $base = [ordered]@{
        timestamp = $State.Timestamp
        hostname = $State.Hostname
        username = Get-DisplayText $State $State.User
        claude_dir = Get-DisplayText $State $State.ClaudeDir
        summary = $summary
    }
    if (-not $SummaryOnly) {
        $base.findings = @($State.Findings | ForEach-Object {
            [ordered]@{
                severity = $_.severity
                section = $_.section
                message = Get-DisplayText $State $_.message
                detail = Get-DisplayText $State $_.detail
            }
        })
        foreach ($section in $script:ReportSections) {
            $base[$section.Json] = @($State[$section.Key] | ForEach-Object {
                $copy = [ordered]@{}
                foreach ($property in $_.PSObject.Properties) {
                    $copy[$property.Name] = Get-DisplayText $State $property.Value
                }
                [pscustomobject]$copy
            })
        }
    }
    [pscustomobject]$base
}

function Write-TerminalReport($State) {
    $summary = Get-Summary $State
    if ($script:Options.Summary) {
        Write-Output "$(Get-DisplayText $State $State.User)  WARN=$($summary.warn) REVIEW=$($summary.review) INFO=$($summary.info)  $(Get-DisplayText $State $State.ClaudeDir)"
        $shown = 0
        foreach ($finding in $State.Findings) {
            if ($finding.severity -eq 'INFO') { continue }
            Write-Output "  [$($finding.severity)] $($finding.section): $(Get-DisplayText $State $finding.message)"
            if (++$shown -ge 8) { break }
        }
        return
    }
    Write-Output ''
    Write-Output "CLAUDE-AUDIT v$($script:Version) - Claude Code local security audit (Windows)"
    Write-Output "User: $(Get-DisplayText $State $State.User)"
    Write-Output "Claude home: $(Get-DisplayText $State $State.ClaudeDir)"
    Write-Output "Findings: WARN=$($summary.warn) REVIEW=$($summary.review) INFO=$($summary.info)"
    Write-Output ''
    if (-not $script:Options.Quiet -or $summary.warn -gt 0 -or $summary.review -gt 0) {
        Write-Output 'Findings'
        foreach ($finding in $State.Findings) {
            if ($script:Options.Quiet -and $finding.severity -eq 'INFO') { continue }
            Write-Output ('  [{0}] {1,-16} {2}' -f $finding.severity, $finding.section, (Get-DisplayText $State $finding.message))
            if ($finding.detail) { Write-Output "       $(Get-DisplayText $State $finding.detail)" }
        }
        Write-Output ''
    }
    foreach ($section in $script:ReportSections) {
        Write-Output $section.Title
        $items = @($State[$section.Key])
        if ($items.Count -eq 0) { Write-Output '  none' }
        else {
            foreach ($item in $items) {
                $first = Get-DisplayText $State $item.($section.First)
                $detail = ($item.PSObject.Properties | Where-Object Name -ne $section.First | ForEach-Object {
                    "$($_.Name)=$(Get-DisplayText $State $_.Value)"
                }) -join ' '
                Write-Output ('  {0,-22} {1}' -f $first, $detail)
            }
        }
        Write-Output ''
    }
}

function ConvertTo-HtmlEncoded([AllowNull()][object]$Value) {
    [Net.WebUtility]::HtmlEncode([string]$Value)
}

function New-HtmlReport($States) {
    $builder = [Text.StringBuilder]::new()
    [void]$builder.AppendLine('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CLAUDE-AUDIT Report</title>')
    [void]$builder.AppendLine('<style>body{margin:0;background:#0d1117;color:#e6edf3;font-family:"Segoe UI",sans-serif}main{max-width:1180px;margin:auto;padding:32px 20px}h2{margin-top:28px}.meta{color:#8b949e}.summary{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:20px 0}.summary div{background:#161b22;border:1px solid #30363d;padding:12px}.summary span{display:block;color:#8b949e}.summary strong{font-size:24px}table{width:100%;border-collapse:collapse;border:1px solid #30363d}th,td{padding:9px 10px;border-bottom:1px solid #30363d;text-align:left;vertical-align:top;font-size:13px}th{color:#8b949e;background:#161b22}code{color:#cae8ff;white-space:pre-wrap;word-break:break-word}.badge{padding:2px 6px;font-weight:700}.WARN{background:#5c1f1f;color:#ffa198}.REVIEW{background:#3d2f00;color:#f0c846}.INFO{background:#0c2a4a;color:#79c0ff}</style></head><body><main>')
    foreach ($state in $States) {
        $summary = Get-Summary $state
        [void]$builder.AppendLine("<section><h1>CLAUDE-AUDIT</h1><p class=`"meta`">User: <strong>$(ConvertTo-HtmlEncoded (Get-DisplayText $state $state.User))</strong> &middot; Host: <strong>$(ConvertTo-HtmlEncoded $state.Hostname)</strong> &middot; Generated: <strong>$(ConvertTo-HtmlEncoded $state.Timestamp)</strong></p>")
        [void]$builder.AppendLine("<p class=`"meta`">Claude home: <code>$(ConvertTo-HtmlEncoded (Get-DisplayText $state $state.ClaudeDir))</code></p><div class=`"summary`"><div><span>WARN</span><strong>$($summary.warn)</strong></div><div><span>REVIEW</span><strong>$($summary.review)</strong></div><div><span>INFO</span><strong>$($summary.info)</strong></div></div>")
        [void]$builder.AppendLine('<h2>Findings</h2><table><thead><tr><th>Severity</th><th>Section</th><th>Finding</th><th>Detail</th></tr></thead><tbody>')
        foreach ($finding in $state.Findings) {
            if ($script:Options.Quiet -and $finding.severity -eq 'INFO') { continue }
            [void]$builder.AppendLine("<tr><td><span class=`"badge $($finding.severity)`">$($finding.severity)</span></td><td>$(ConvertTo-HtmlEncoded $finding.section)</td><td>$(ConvertTo-HtmlEncoded (Get-DisplayText $state $finding.message))</td><td><code>$(ConvertTo-HtmlEncoded (Get-DisplayText $state $finding.detail))</code></td></tr>")
        }
        [void]$builder.AppendLine('</tbody></table>')
        foreach ($section in $script:ReportSections) {
            [void]$builder.AppendLine("<h2>$(ConvertTo-HtmlEncoded $section.Title)</h2><table><tbody>")
            $items = @($state[$section.Key])
            if ($items.Count -eq 0) {
                [void]$builder.AppendLine('<tr><td>none</td><td></td></tr>')
            } else {
                foreach ($item in $items) {
                    $first = ConvertTo-HtmlEncoded (Get-DisplayText $state $item.($section.First))
                    $detail = ($item.PSObject.Properties | Where-Object Name -ne $section.First | ForEach-Object {
                        "$($_.Name)=$(Get-DisplayText $state $_.Value)"
                    }) -join ' | '
                    [void]$builder.AppendLine("<tr><td>$first</td><td><code>$(ConvertTo-HtmlEncoded $detail)</code></td></tr>")
                }
            }
            [void]$builder.AppendLine('</tbody></table>')
        }
        [void]$builder.AppendLine('</section>')
    }
    [void]$builder.AppendLine('</main></body></html>')
    $builder.ToString()
}

function Get-AuditTargets {
    if ($script:Options.AllUsers) {
        return @(Get-ChildItem -LiteralPath (Join-Path $env:SystemDrive 'Users') -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object {
                (Test-Path -LiteralPath (Join-Path $_.FullName '.claude') -PathType Container) -or
                (Test-Path -LiteralPath (Join-Path $_.FullName '.claude.json') -PathType Leaf)
            } | ForEach-Object {
                [pscustomobject]@{ User = $_.Name; Home = $_.FullName }
            })
    }
    $user = if ($script:Options.User) { $script:Options.User } else { [Environment]::UserName }
    $userHome = if ($script:Options.User -and $script:Options.User -ne [Environment]::UserName) {
        Join-Path (Join-Path $env:SystemDrive 'Users') $script:Options.User
    } else {
        [Environment]::GetFolderPath('UserProfile')
    }
    @([pscustomobject]@{ User = $user; Home = $userHome })
}

$targets = @(Get-AuditTargets)
if ($targets.Count -eq 0) {
    [Console]::Error.WriteLine('No users with Claude Code data found.')
    exit 1
}

$states = @($targets | ForEach-Object { Invoke-Audit $_.User $_.Home })
$content = if ($script:Options.Json) {
    $objects = @($states | ForEach-Object { Convert-StateForOutput $_ -SummaryOnly:$script:Options.Summary })
    $jsonObject = if ($objects.Count -eq 1) { $objects[0] } else { $objects }
    $jsonObject | ConvertTo-Json -Depth 12
} elseif ($script:Options.Html) {
    New-HtmlReport $states
} else {
    $lines = @($states | ForEach-Object { Write-TerminalReport $_ })
    $lines -join [Environment]::NewLine
}

if ($script:Options.Html) {
    $path = if ($script:Options.Output) { $script:Options.Output }
        elseif ($script:Options.Html -eq 'AUTO') { "claude_audit_$([DateTime]::Now.ToString('yyyyMMdd_HHmmss')).html" }
        else { $script:Options.Html }
    [IO.File]::WriteAllText([IO.Path]::GetFullPath($path), $content, [Text.UTF8Encoding]::new($false))
    Write-Output "HTML report written: $path"
} elseif ($script:Options.Output) {
    [IO.File]::WriteAllText([IO.Path]::GetFullPath($script:Options.Output), $content, [Text.UTF8Encoding]::new($false))
} else {
    Write-Output $content
}

$exitCode = 0
foreach ($state in $states) {
    $summary = Get-Summary $state
    if ($script:Options.FailOn -eq 'warn' -and $summary.warn -gt 0) { $exitCode = 2 }
    elseif ($script:Options.FailOn -eq 'review' -and $summary.review -gt 0 -and $exitCode -eq 0) { $exitCode = 1 }
}
exit $exitCode
