# claude-egress-guard - shared definitions for the Windows scripts (dot-sourced).
# Keep this file ASCII-only: Windows PowerShell 5.1 reads BOM-less UTF-8 as the ANSI code page.

$CegGroup = 'ClaudeEgressGuard'
# ProgramW6432 = the 64-bit "Program Files" even from a 32-bit PowerShell (where ProgramFiles is x86)
$CegProgramFiles = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
$CegManagedDir = Join-Path $CegProgramFiles 'ClaudeCode'
$CegManagedFile = Join-Path $CegManagedDir 'managed-settings.json'
# State of the managed settings BEFORE the first install. Kept next to the managed file because
# Program Files is admin-only (ProgramData subfolders are user-writable by default, so a marker
# there could be forged to turn "restore" into "delete").
$CegOrigFile = "$CegManagedFile.ceg-orig"        # copy of the pre-install file
$CegCreatedMarker = "$CegManagedFile.ceg-created" # the file did not exist before install

# Every public address: the complement of loopback, RFC1918, CGNAT/Tailscale (100.64/10) and
# link-local, plus IPv6 global unicast and the NAT64 prefixes (on IPv6-only networks with
# DNS64, 64:ff9b::/96 reaches any IPv4 host). A program blocked to this list can only reach the
# local proxy, the LAN and Tailscale peers.
$CegPublicRanges = @(
  '0.0.0.0-9.255.255.255', '11.0.0.0-100.63.255.255', '100.128.0.0-126.255.255.255',
  '128.0.0.0-169.253.255.255', '169.255.0.0-172.15.255.255', '172.32.0.0-192.167.255.255',
  '192.169.0.0-255.255.255.255', '2000::/3', '64:ff9b::/96', '64:ff9b:1::/48'
)

function Get-CegAnthropicRanges {
  <# Read config\anthropic-ranges.txt (non-comment lines). Throws when the list is empty or an
     entry is not an IP prefix, BEFORE any firewall rule is touched. #>
  param([string]$Root)
  $file = Join-Path $Root 'config\anthropic-ranges.txt'
  $ranges = @(Get-Content $file | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
  if ($ranges.Count -eq 0) { throw "$file contains no address ranges" }
  foreach ($r in $ranges) {
    $parts = $r -split '/'
    $ip = $null
    if ($parts.Count -ne 2 -or -not [Net.IPAddress]::TryParse($parts[0], [ref]$ip) -or $parts[1] -notmatch '^\d{1,3}$') {
      throw "$file has an invalid entry: '$r'"
    }
  }
  $ranges
}

function Assert-CegNoProxy {
  <# Refuse NO_PROXY values that would send Claude-related hosts DIRECT ('*', or an entry that
     covers a domain of config\claude-domains.txt as a suffix, e.g. '.com'). #>
  param([string]$Root, [string]$NoProxy)
  $domains = @(Get-Content (Join-Path $Root 'config\claude-domains.txt') |
    ForEach-Object { ($_ -split '#')[0].Trim().ToLower() } | Where-Object { $_ })
  foreach ($e in ($NoProxy.ToLower() -split '[,\s]+' | Where-Object { $_ })) {
    if ($e -eq '*') { throw "-NoProxy must not contain '*' (Claude Code would go direct)" }
    $h = ($e -replace '^\*', '' -replace '^\.', '' -replace ':\d+$', '')
    if (-not $h) { continue }
    foreach ($d in $domains) {
      if ($d -eq $h -or $d.EndsWith('.' + $h)) { throw "-NoProxy entry '$e' would send $d DIRECT" }
    }
    if ($h -match 'anthropic|claude') { throw "-NoProxy must not contain Anthropic/Claude domains ('$e')" }
  }
}

function Assert-CegAdmin {
  <# Stop unless the current PowerShell is elevated. #>
  $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this from an elevated PowerShell (Run as administrator), logged in as the Claude Code user.'
  }
}

function Write-CegJsonNoBom {
  <# Write JSON as UTF-8 WITHOUT a BOM (a BOM can break JSON parsers). #>
  param([string]$Path, [object]$Object)
  $json = $Object | ConvertTo-Json -Depth 20
  [IO.File]::WriteAllText($Path, $json, (New-Object Text.UTF8Encoding($false)))
}
