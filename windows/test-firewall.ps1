<#
.SYNOPSIS
  claude-egress-guard - verify the firewall design without touching Claude Code (elevated).
.DESCRIPTION
  1. Creates a temporary "twin" of the "Claude Code only local" rule for curl.exe and checks:
     direct to a public site = blocked, via the local proxy = allowed, LAN gateway = allowed.
     The twin rule is always removed afterwards.
  2. Checks the real "Block Anthropic" rule: direct to Anthropic = blocked, via proxy = works.
     The direct attempt runs ONLY after confirming that the rule exists, is enabled and the
     firewall is on for every profile - otherwise it is skipped, so a broken install cannot
     make this test itself connect to Anthropic from your real IP.
  3. Compares the "Claude Code only local" rule's program path with the claude.exe you run.
.EXAMPLE
  .\test-firewall.ps1 -ProxyUrl http://127.0.0.1:10808
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$ProxyUrl,
  [string]$PublicTestUrl = 'https://github.com',
  [string]$LanTestUrl = ''
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
Assert-CegAdmin
$curl = Join-Path $env:SystemRoot 'System32\curl.exe'
if (-not $LanTestUrl) {
  $gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Sort-Object RouteMetric | Select-Object -First 1).NextHop
  $LanTestUrl = if ($gw) { "http://$gw" } else { '' }
}

function Test-Url {
  <# Print curl's status for one request; extra args are passed through. #>
  param([string]$Label, [string[]]$CurlArgs)
  $r = & $curl -s -m 8 -o NUL -w 'http=%{http_code} t=%{time_total}s' @CurlArgs 2>&1
  Write-Host ('  {0,-46} {1}' -f $Label, $r)
}

$twin = "$CegGroup - TEST twin (temporary)"
try {
  Write-Host '1) twin rule on curl.exe (same ranges as "Claude Code only local")'
  New-NetFirewallRule -DisplayName $twin -Group $CegGroup -Direction Outbound -Action Block `
    -Program $curl -RemoteAddress $CegPublicRanges -Profile Any | Out-Null
  Start-Sleep 1
  Test-Url 'direct public (expect http=000)' @('--noproxy', '*', $PublicTestUrl)
  Test-Url 'via local proxy (expect 2xx/3xx)' @('-x', $ProxyUrl, $PublicTestUrl)
  if ($LanTestUrl) { Test-Url "LAN gateway $LanTestUrl (expect not blocked)" @('--noproxy', '*', $LanTestUrl) }
  else { Write-Host '  (no IPv4 default gateway - LAN test skipped; pass -LanTestUrl)' }
} finally {
  Get-NetFirewallRule -DisplayName $twin -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  Write-Host '  twin rule removed'
}

Write-Host '2) "Block Anthropic (all programs)"'
$rule = Get-NetFirewallRule -DisplayName "$CegGroup - Block Anthropic (all programs)" -ErrorAction SilentlyContinue
$profilesOff = @(Get-NetFirewallProfile | Where-Object { $_.Enabled -ne 'True' } | ForEach-Object { $_.Name })
if (-not $rule -or $rule.Enabled -ne 'True' -or $profilesOff.Count -gt 0) {
  Write-Warning ("rule missing/disabled or firewall off for: {0} - SKIPPING the direct test (it would reach Anthropic). Re-run install.ps1." -f ($(if ($profilesOff) { $profilesOff -join ',' } else { 'rule' })))
} else {
  $first = (Get-CegAnthropicRanges -Root (Split-Path -Parent $PSScriptRoot)) | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+/' } | Select-Object -First 1
  $ip = ($first -split '/')[0] -replace '\.0$', '.10'
  Test-Url "direct https://$ip (expect http=000)" @('--noproxy', '*', "https://$ip/")
  # only with the block rule in force: a proxy wrongly in "direct" mode is then refused too
  $trace = & $curl -s -m 15 -x $ProxyUrl https://api.anthropic.com/cdn-cgi/trace 2>&1
  Write-Host ('  {0,-46} {1}' -f 'via proxy: exit Anthropic sees', (($trace | Select-String '^(ip|loc)=') -join ' '))
}

Write-Host '3) "Claude Code only local" covers the claude.exe you run?'
$local = Get-NetFirewallRule -DisplayName "$CegGroup - Claude Code only local" -ErrorAction SilentlyContinue
if (-not $local) {
  Write-Warning 'rule not installed'
} else {
  $ruleExe = ($local | Get-NetFirewallApplicationFilter).Program
  $used = @(Get-Process claude -ErrorAction SilentlyContinue | ForEach-Object { $_.Path }) +
          @(Get-Command claude -ErrorAction SilentlyContinue | Where-Object { $_.Source -like '*.exe' } | ForEach-Object { $_.Source })
  $used = @($used | Where-Object { $_ } | Select-Object -Unique)
  Write-Host "  rule program: $ruleExe (enabled=$($local.Enabled))"
  if (-not $used) { Write-Host '  no running/PATH claude.exe found to compare' }
  foreach ($u in $used) {
    Write-Host ('  {0,-46} {1}' -f $u, $(if ($u -eq $ruleExe) { 'covered' } else { 'NOT covered - re-run install.ps1 -ClaudeExe' }))
  }
}
