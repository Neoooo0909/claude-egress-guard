<#
.SYNOPSIS
  claude-egress-guard - Windows installer.

.DESCRIPTION
  Run from an ELEVATED PowerShell while logged in as the user who runs Claude Code.
    1. User environment: NODE_USE_ENV_PROXY=1 (optionally HTTP(S)_PROXY / NO_PROXY).
    2. Claude Code managed settings (64-bit %ProgramFiles%\ClaudeCode\managed-settings.json):
       proxy variables with the highest precedence (merged; the pre-install state is recorded
       once, on the first install, and restored by uninstall.ps1).
    3. Windows Firewall, group "ClaudeEgressGuard":
       a) "Block Anthropic (all programs)" - no process may reach config\anthropic-ranges.txt
          directly; only your remote proxy exit should.
       b) "Claude Code only local" - the native claude.exe may only reach loopback (your local
          proxy), the LAN and Tailscale. Requires the native build (npm builds run as node.exe,
          which other tools share).
    4. Block log (skip with -NoBlockLog): enables failure auditing of "Filtering Platform
       Connection" (event 5157), raises the Security log to at least 128 MB (that audit also
       records unrelated inbound drops), and registers the SYSTEM task "ClaudeEgressGuard-BlockLog"
       which copies the events of the rules above to %ProgramData%\ClaudeEgressGuard\blocked.jsonl.
       View with blocked.ps1. uninstall.ps1 restores the audit setting and the log size.
  Windows Firewall cannot filter per USER. Rule (b) matches the claude.exe image only: its
  child processes (MCP servers, git, curl/python run by the Bash tool) are NOT restricted by
  it - they are covered by rule (a) for Anthropic addresses and by your proxy variables for
  everything else. This is weaker than the per-user pf rule of the macOS full mode.

.EXAMPLE
  .\install.ps1 -ProxyUrl http://127.0.0.1:10808
.EXAMPLE
  .\install.ps1 -ProxyUrl http://127.0.0.1:7890 -SetUserProxyEnv -NoProxy "localhost,127.0.0.1,::1,192.168.0.0/16"
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$ProxyUrl,
  [string]$NoProxy = 'localhost,127.0.0.1,::1',
  [string]$ClaudeExe = (Join-Path $env:USERPROFILE '.local\bin\claude.exe'),
  [switch]$SetUserProxyEnv,
  [switch]$SkipManagedSettings,
  [switch]$SkipClaudeRule,
  [switch]$NoBlockLog
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
Assert-CegAdmin
$Root = Split-Path -Parent $PSScriptRoot
# Validate inputs before changing anything (an empty/bad range list must not remove the old rules)
if ($ProxyUrl -notmatch '^https?://[A-Za-z0-9._-]+:\d{1,5}/?$') {
  throw "-ProxyUrl must look like http://127.0.0.1:10808 (no credentials, no path)"
}
Assert-CegNoProxy -Root $Root -NoProxy $NoProxy
$anthropic = Get-CegAnthropicRanges -Root $Root

# 1. user environment ------------------------------------------------------------------
[Environment]::SetEnvironmentVariable('NODE_USE_ENV_PROXY', '1', 'User')
if ($SetUserProxyEnv) {
  foreach ($n in 'HTTP_PROXY', 'HTTPS_PROXY') { [Environment]::SetEnvironmentVariable($n, $ProxyUrl, 'User') }
  [Environment]::SetEnvironmentVariable('NO_PROXY', $NoProxy, 'User')
}
Write-Host "[1/4] user env: NODE_USE_ENV_PROXY=1$(if ($SetUserProxyEnv) { ", HTTP(S)_PROXY=$ProxyUrl" })"

# 2. managed settings --------------------------------------------------------------------
if (-not $SkipManagedSettings) {
  New-Item -ItemType Directory -Force $CegManagedDir | Out-Null
  $obj = [pscustomobject]@{}
  $exists = Test-Path $CegManagedFile
  if ($exists) {
    $raw = Get-Content $CegManagedFile -Raw
    if ($raw -and $raw.Trim()) {
      try { $obj = $raw | ConvertFrom-Json }
      catch {
        # Windows PowerShell 5.1 cannot parse keys that differ only in case (e.g. HTTP_PROXY + http_proxy)
        throw "Cannot parse $CegManagedFile ($($_.Exception.Message)). Merge the env block by hand; nothing was changed."
      }
    }
  }
  # Record the ORIGINAL state only on the first install, so re-running install.ps1 never
  # overwrites it with an already-modified file
  if (-not (Test-Path $CegOrigFile) -and -not (Test-Path $CegCreatedMarker)) {
    if ($exists) { Copy-Item $CegManagedFile $CegOrigFile }
    else { New-Item -ItemType File -Force $CegCreatedMarker | Out-Null }
  }
  if (-not ($obj.PSObject.Properties.Name -contains 'env')) {
    $obj | Add-Member -NotePropertyName env -NotePropertyValue ([pscustomobject]@{})
  }
  # Upper-case only: environment variable names are case-insensitive on Windows, and PowerShell
  # objects/hashtables cannot hold keys that differ only in case.
  $vals = [ordered]@{ HTTP_PROXY = $ProxyUrl; HTTPS_PROXY = $ProxyUrl; NO_PROXY = $NoProxy; NODE_USE_ENV_PROXY = '1' }
  foreach ($k in $vals.Keys) { $obj.env | Add-Member -NotePropertyName $k -NotePropertyValue $vals[$k] -Force }
  Write-CegJsonNoBom -Path $CegManagedFile -Object $obj
  Write-Host "[2/4] managed settings: $CegManagedFile"
} else { Write-Host '[2/4] managed settings skipped' }

# 3. firewall ------------------------------------------------------------------------------
Get-NetFirewallRule -Group $CegGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName "$CegGroup - Block Anthropic (all programs)" -Group $CegGroup `
  -Direction Outbound -Action Block -RemoteAddress $anthropic -Profile Any `
  -Description 'No process may reach Anthropic directly; only via the proxy exit.' | Out-Null

if (-not $SkipClaudeRule) {
  $cmd = Get-Command claude -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($cmd -and $cmd.Source -match '\\npm\\') {
    Write-Warning "claude on PATH is the npm build ($($cmd.Source)). Run 'claude install' to switch to the native build, then re-run this script."
  } elseif ($cmd -and $cmd.Source -like '*.exe' -and $cmd.Source -ne $ClaudeExe) {
    Write-Warning "claude on PATH is $($cmd.Source), not $ClaudeExe - re-run with -ClaudeExe '$($cmd.Source)' if that is the one you use."
  }
  # A running Claude Code tells us the real image path (the rule matches the exact path)
  Get-Process claude -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path -ne $ClaudeExe } |
    Select-Object -ExpandProperty Path -Unique | ForEach-Object {
      Write-Warning "a running claude process uses $_ - the rule below does NOT cover it (use -ClaudeExe)."
    }
  if (Test-Path $ClaudeExe) {
    New-NetFirewallRule -DisplayName "$CegGroup - Claude Code only local" -Group $CegGroup `
      -Direction Outbound -Action Block -Program $ClaudeExe -RemoteAddress $CegPublicRanges -Profile Any `
      -Description 'claude.exe may only reach loopback (local proxy), LAN and Tailscale.' | Out-Null
  } else {
    Write-Warning "$ClaudeExe not found - 'Claude Code only local' rule NOT created."
  }
}
Write-Host '[3/4] firewall rules:'
Get-NetFirewallRule -Group $CegGroup | ForEach-Object {
  $app = ($_ | Get-NetFirewallApplicationFilter).Program
  Write-Host ("   {0}  (program: {1})" -f $_.DisplayName, $app)
}

# 4. block log -----------------------------------------------------------------------------
if (-not $NoBlockLog) {
  New-Item -ItemType Directory -Force $CegToolDir | Out-Null
  # Record the pre-install state once (first install only), for uninstall.ps1
  if (-not (Test-Path $CegAuditOrig)) { Set-Content -Encoding ASCII $CegAuditOrig (Get-CegAuditValue) }
  $secMax = (Get-WinEvent -ListLog Security).MaximumSizeInBytes
  if (-not (Test-Path $CegSecLogOrig)) { Set-Content -Encoding ASCII $CegSecLogOrig $secMax }
  auditpol /set /subcategory:$CegAuditGuid /failure:enable | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "auditpol /set failed ($LASTEXITCODE)" }
  if ($secMax -lt 128MB) {
    wevtutil sl Security /ms:134217728
    # e.g. the size is managed by Group Policy: the block log still works, older events rotate sooner
    if ($LASTEXITCODE -ne 0) { Write-Warning 'could not raise the Security log size (policy-managed?); continuing' }
  }
  Copy-Item -Force (Join-Path $PSScriptRoot 'blocklog.ps1') (Join-Path $CegToolDir 'blocklog.ps1')
  Copy-Item -Force (Join-Path $PSScriptRoot 'blocked.ps1') (Join-Path $CegToolDir 'blocked.ps1')
  Copy-Item -Force (Join-Path $Root 'config\anthropic-ranges.txt') (Join-Path $CegToolDir 'anthropic-ranges.txt')
  # Data folder: SYSTEM/Administrators write, the installing user reads (destinations reveal activity).
  # The SYSTEM task writes here, so a folder a normal user created in advance (owner = that user,
  # who could re-grant himself access) or a junction must not be reused: recreate it.
  if (Test-Path -LiteralPath $CegDataDir) {
    $item = Get-Item -LiteralPath $CegDataDir -Force
    $owner = (Get-Acl -LiteralPath $CegDataDir).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or -not $item.PSIsContainer -or
        ($owner -ne 'S-1-5-18' -and $owner -ne 'S-1-5-32-544')) {
      Write-Warning "$CegDataDir existed with an unexpected owner/type - recreating it"
      if ($item.PSIsContainer) { Remove-CegDirectory $CegDataDir } else { Remove-Item -LiteralPath $CegDataDir -Force }
    }
  }
  New-Item -ItemType Directory -Force $CegDataDir | Out-Null
  $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  icacls $CegDataDir /setowner '*S-1-5-32-544' | Out-Null
  icacls $CegDataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*${me}:(OI)(CI)RX" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'icacls failed' }
  $query = "&lt;QueryList&gt;&lt;Query Id=`"0`" Path=`"Security`"&gt;&lt;Select Path=`"Security`"&gt;*[System[EventID=5157]] and *[EventData[Data[@Name='Direction']='%%14593']]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;"
  $collector = Join-Path $CegToolDir 'blocklog.ps1'
  $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>claude-egress-guard: copy connections blocked by the $CegGroup firewall rules to $CegDataDir\blocked.jsonl</Description></RegistrationInfo>
  <Triggers>
    <EventTrigger><Enabled>true</Enabled><Subscription>$query</Subscription></EventTrigger>
    <TimeTrigger><Repetition><Interval>PT30M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>2025-01-01T00:00:00</StartBoundary><Enabled>true</Enabled></TimeTrigger>
  </Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Hidden>true</Hidden>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec><Command>powershell.exe</Command><Arguments>-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "$collector"</Arguments></Exec>
  </Actions>
</Task>
"@
  Register-ScheduledTask -TaskName $CegBlockTask -Xml $xml -Force | Out-Null
  Write-Host "[4/4] block log: task $CegBlockTask, log $CegDataDir\blocked.jsonl"
  Write-Host "      view: powershell -ExecutionPolicy Bypass -File `"$CegToolDir\blocked.ps1`""
} else {
  Write-Host '[4/4] block log skipped'
  if (Get-ScheduledTask -TaskName $CegBlockTask -ErrorAction SilentlyContinue) {
    Write-Warning "a block log from an earlier install is still active; uninstall.ps1 removes it"
  }
}
Write-Host 'Verify with: .\test-firewall.ps1 -ProxyUrl' $ProxyUrl
