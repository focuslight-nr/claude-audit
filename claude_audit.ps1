# CLAUDE-AUDIT - Claude Code local security audit tool (Windows/PowerShell)
# Read-only audit for Claude Code and Claude Desktop configuration.
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CliArgs
)

$ErrorActionPreference = 'Stop'
$script:Version = '0.1.0'
$script:DangerousMcpHints = @(
    'bash', 'sh', 'zsh', 'cmd', 'cmd.exe', 'powershell', 'powershell.exe',
    'pwsh', 'pwsh.exe', 'python', 'python.exe', 'python3', 'node', 'node.exe',
    'ruby', 'perl', 'wscript', 'wscript.exe', 'cscript', 'cscript.exe',
    'mshta', 'mshta.exe', 'curl', 'curl.exe', 'wget', 'ssh', 'scp'
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
        ActiveSessions = [Collections.Generic.List[object]]::new()
        SensitiveFiles = [Collections.Generic.List[object]]::new()
        Retention = [Collections.Generic.List[object]]::new()
        SeenMcp = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
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
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    $null
}

function Get-ObjectEntries($Object) {
    if ($null -eq $Object) { return @() }
    @($Object.PSObject.Properties | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; Value = $_.Value }
    })
}

function Join-Values($Value) {
    if ($null -eq $Value) { return '' }
    @($Value) -join ', '
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

function Get-McpEnvRiskTags([string]$Keys) {
    $tags = [Collections.Generic.List[string]]::new()
    if ($Keys -match '(?i)(token|secret|password|passwd|api[_-]?key|credential|auth|cookie)') { $tags.Add('secret-like-env') }
    if ($Keys -match '(?i)(trusted|allowlist)') { $tags.Add('trust-or-allowlist') }
    if ($Keys -match '(?i)(path|dirs|home)') { $tags.Add('filesystem-scope') }
    if ($Keys -match '(?i)(browser|backend)') { $tags.Add('browser-scope') }
    $tags -join ','
}

function Get-HookRiskTags([string]$Command) {
    $tags = [Collections.Generic.List[string]]::new()
    if ($Command -match '(?i)(curl|wget|https?://|Invoke-WebRequest|Invoke-RestMethod)') { $tags.Add('network') }
    if ($Command -match '(?i)(\brm\b|Remove-Item|\bdel\b|erase|rmdir)') { $tags.Add('destructive') }
    if ($Command -match '(?i)git\s+(push|commit)') { $tags.Add('git-write') }
    if ($Command -match '(?i)(Start-Process|mshta|wscript|cscript)') { $tags.Add('gui-or-script-host') }
    if ($Command -match '(?i)(RunAs|Start-Process.+-Verb\s+RunAs)') { $tags.Add('elevated-privilege') }
    $tags -join ','
}

function Get-RedactedValue([string]$Key, [AllowNull()][object]$Value) {
    $text = if ($null -eq $Value) { '' } else { [string]$Value }
    if ($Key -match '(?i)(token|secret|password|passwd|api[_-]?key|credential|auth|session|cookie)' -or
        $text -match '(?i)(sk-ant-|bearer |token=|secret=|password=|api[_-]?key=)') {
        return '[REDACTED]'
    }
    $text
}

function Add-McpServersFromJson($State, [string]$Path, [string]$Source) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $json = Read-JsonFile $Path
    if ($null -eq $json) {
        Add-Finding $State 'REVIEW' 'Config' 'Unable to parse JSON configuration' $Path
        return
    }
    foreach ($entry in (Get-ObjectEntries (Get-Property $json 'mcpServers'))) {
        $server = $entry.Value
        $key = "$($entry.Name)|$Source"
        if (-not $State.SeenMcp.Add($key)) { continue }
        $commandValue = Get-Property $server 'command'
        if (-not $commandValue) { $commandValue = Get-Property $server 'url' }
        $command = [string]$commandValue
        $args = Join-Values (Get-Property $server 'args')
        $envKeys = (Get-ObjectEntries (Get-Property $server 'env') | ForEach-Object Name) -join ', '
        $type = [string](Get-Property $server 'type')
        if (-not $type) { $type = 'stdio' }
        $riskTags = Get-McpEnvRiskTags $envKeys
        $State.McpServers.Add([pscustomobject]@{
            name = "$($entry.Name)($Source)"
            type = $type
            command = Get-RedactedValue 'command' $command
            args = Get-RedactedValue 'args' $args
            env_keys = $envKeys
            env_risk_tags = $riskTags
        })
        Add-Finding $State 'REVIEW' 'MCP Servers' "MCP server configured: $($entry.Name)" "source=$Source; type=$type; command=$(if ($command) {$command} else {'unknown'}); env_keys=$(if ($envKeys) {$envKeys} else {'none'})"
        if ($riskTags) {
            Add-Finding $State 'REVIEW' 'MCP Servers' "MCP server env keys imply elevated scope: $($entry.Name)" $riskTags
        }
        $base = [IO.Path]::GetFileName($command).ToLowerInvariant()
        if ($base -in $script:DangerousMcpHints) {
            Add-Finding $State 'WARN' 'MCP Servers' "MCP server uses command-capable runtime: $($entry.Name)" $command
        }
    }
}

function Add-HookCommands($State, [string]$Event, [string]$Source, $Item) {
    $commands = [Collections.Generic.List[string]]::new()
    foreach ($candidate in @($Item)) {
        if ($candidate -is [string]) {
            $commands.Add($candidate)
            continue
        }
        $direct = Get-Property $candidate 'command'
        if ($direct) { $commands.Add([string]$direct) }
        foreach ($nested in @((Get-Property $candidate 'hooks'))) {
            if ($nested -is [string]) { $commands.Add($nested) }
            else {
                $nestedCommand = Get-Property $nested 'command'
                if ($nestedCommand) { $commands.Add([string]$nestedCommand) }
            }
        }
    }
    if ($commands.Count -eq 0) {
        $State.Hooks.Add([pscustomobject]@{ event = $Event; source = $Source; command = '(configured)'; risk_tags = '' })
        Add-Finding $State 'REVIEW' 'Hooks' "Hook configured: $Event" "source=$Source"
        return
    }
    foreach ($command in $commands) {
        $risk = Get-HookRiskTags $command
        $State.Hooks.Add([pscustomobject]@{ event = $Event; source = $Source; command = $command; risk_tags = $risk })
        $short = if ($command.Length -gt 80) { $command.Substring(0, 80) } else { $command }
        Add-Finding $State 'REVIEW' 'Hooks' "Hook configured: $Event" "source=$Source; cmd=$short$(if ($risk) {"; risk=$risk"})"
        if ($risk) { Add-Finding $State 'WARN' 'Hooks' "Hook has elevated risk: $Event" "risk=$risk; cmd=$short" }
    }
}

function Collect-SettingsFile($State, [string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    Add-McpServersFromJson $State $Path $Label
    $json = Read-JsonFile $Path
    if ($null -eq $json) { return }
    foreach ($hook in (Get-ObjectEntries (Get-Property $json 'hooks'))) {
        Add-HookCommands $State $hook.Name $Label $hook.Value
    }
    $permissions = Get-Property $json 'permissions'
    $allowed = Join-Values (Get-Property $permissions 'allow')
    $denied = Join-Values (Get-Property $permissions 'deny')
    if ($allowed) { Add-Finding $State 'REVIEW' 'Permissions' "Pre-approved tools in settings ($Label)" $allowed }
    if ($denied) { Add-Finding $State 'INFO' 'Permissions' "Denied tools in settings ($Label)" $denied }
    $model = Get-Property $json 'model'
    if ($model) { Add-Finding $State 'INFO' 'Config' "Model override in settings ($Label): $model" }
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
    $model = Get-Property $json 'model'
    if ($model) { Add-Finding $State 'INFO' 'Config' "Default model: $model" }
    $userId = [string](Get-Property $json 'userID')
    if ($userId) {
        $prefix = $userId.Substring(0, [Math]::Min(16, $userId.Length))
        Add-Finding $State 'INFO' 'Config' 'User ID present' "$prefix..."
    }
    foreach ($project in (Get-ObjectEntries (Get-Property $json 'projects'))) {
        $value = $project.Value
        $trusted = (Get-Property $value 'hasTrustDialogAccepted') -eq $true
        $allowed = Join-Values (Get-Property $value 'allowedTools')
        $enabled = Join-Values (Get-Property $value 'enabledMcpjsonServers')
        $disabled = Join-Values (Get-Property $value 'disabledMcpjsonServers')
        $State.Projects.Add([pscustomobject]@{
            path = $project.Name
            detail = "trust=$($trusted.ToString().ToLowerInvariant())|tools=$(if ($allowed) {$allowed} else {'none'})|mcp_enabled=$(if ($enabled) {$enabled} else {'none'})|mcp_disabled=$(if ($disabled) {$disabled} else {'none'})"
        })
        if ($trusted) { Add-Finding $State 'WARN' 'Projects' 'Trusted project grants Claude Code broader workspace autonomy' $project.Name }
        if ($allowed) {
            Add-Finding $State 'REVIEW' 'Projects' "Project has pre-approved tools: $([IO.Path]::GetFileName($project.Name))" $allowed
        }
        if ($enabled) {
            Add-Finding $State 'INFO' 'Projects' "Project has enabled MCP .json servers: $([IO.Path]::GetFileName($project.Name))" $enabled
        }
        if (Test-Path -LiteralPath $project.Name -PathType Container) {
            Collect-SettingsFile $State (Join-Path $project.Name '.claude\settings.json') "project:$([IO.Path]::GetFileName($project.Name))"
            Collect-SettingsFile $State (Join-Path $project.Name '.claude\settings.local.json') "project-local:$([IO.Path]::GetFileName($project.Name))"
            Add-McpServersFromJson $State (Join-Path $project.Name '.mcp.json') "project-mcp:$([IO.Path]::GetFileName($project.Name))"
        }
    }
    if ($State.Projects.Count -gt 0) { Add-Finding $State 'INFO' 'Projects' "$($State.Projects.Count) project(s) in config" }
    foreach ($entry in (Get-ObjectEntries (Get-Property $json 'bypassPermissionsGateByAccount'))) {
        if ($entry.Value -eq $true) {
            Add-Finding $State 'WARN' 'Permissions' 'Bypass permissions gate is ENABLED for account' $entry.Name
        }
    }
    $pluginCount = (Get-ObjectEntries (Get-Property $json 'pluginUsage')).Count
    if ($pluginCount -gt 0) {
        Add-Finding $State 'INFO' 'Skills' "$pluginCount skill/plugin package(s) referenced in usage history"
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

function Format-Bytes([long]$Bytes) {
    if ($Bytes -lt 1KB) { return "$Bytes B" }
    if ($Bytes -lt 1MB) { return '{0:N1} KB' -f ($Bytes / 1KB) }
    if ($Bytes -lt 1GB) { return '{0:N1} MB' -f ($Bytes / 1MB) }
    '{0:N1} GB' -f ($Bytes / 1GB)
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

function Collect-Runtime($State) {
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
    try {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
            $_.TaskName -match '(?i)(claude|anthropic)' -or
            ($_.Actions | Out-String) -match '(?i)(claude|anthropic)'
        })
        foreach ($task in $tasks) {
            Add-Finding $State 'WARN' 'Runtime' 'Claude-related scheduled task found' "$($task.TaskPath)$($task.TaskName)"
        }
    } catch {
        Add-Finding $State 'INFO' 'Runtime' 'Scheduled tasks could not be inspected' $_.Exception.Message
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
        Collect-Desktop $state
        Collect-Runtime $state
        return $state
    }
    Collect-MainConfig $state
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
    $backups = Join-Path $claudeDir 'backups'
    if (Test-Path -LiteralPath $backups -PathType Container) {
        $stats = Get-DirectoryStats $backups
        Add-Finding $state 'INFO' 'Sensitive Files' "backups directory contains $($stats.Count) file(s)" "size=$(Format-Bytes $stats.Bytes)"
    }
    foreach ($name in @('sessions', 'shell-snapshots', 'session-env', 'projects')) {
        Add-RetentionDirectory $state $name (Join-Path $claudeDir $name)
    }
    Collect-Desktop $state
    Collect-Runtime $state
    $state
}

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
        foreach ($pair in @(
            @('mcp_servers', 'McpServers'), @('projects', 'Projects'), @('hooks', 'Hooks'),
            @('active_sessions', 'ActiveSessions'), @('sensitive_files', 'SensitiveFiles'),
            @('retention', 'Retention')
        )) {
            $base[$pair[0]] = @($State[$pair[1]] | ForEach-Object {
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
    foreach ($section in @(
        @('MCP Servers', 'McpServers', 'name'), @('Projects', 'Projects', 'path'),
        @('Hooks', 'Hooks', 'event'), @('Active Sessions', 'ActiveSessions', 'pid'),
        @('Sensitive Files', 'SensitiveFiles', 'name'), @('Retention', 'Retention', 'name')
    )) {
        Write-Output $section[0]
        $items = @($State[$section[1]])
        if ($items.Count -eq 0) { Write-Output '  none' }
        else {
            foreach ($item in $items) {
                $first = Get-DisplayText $State $item.($section[2])
                $detail = ($item.PSObject.Properties | Where-Object Name -ne $section[2] | ForEach-Object {
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
        [void]$builder.AppendLine('</tbody></table></section>')
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
