<#
.SYNOPSIS
  claude-egress-guard - block log collector (installed by install.ps1; runs as SYSTEM).

.DESCRIPTION
  Started by the scheduled task "ClaudeEgressGuard-BlockLog" on every outbound "connection
  blocked" audit event (Security log, event 5157) and every 30 minutes. Copies the events raised
  by OUR firewall rules to <DataDir>\blocked.jsonl, one JSON line per (program, destination, port,
  protocol) and batch. Other software's block rules also raise 5157, so events are matched by
  filter run-time id: ids of the WFP filters named "<Group> - ..." are read from
  "netsh wfp show filters" and cached until reboot (a new, unknown id triggers a re-read).
  If the filter list cannot be read, the batch is left for the next run (nothing is logged
  unverified). The script sends nothing itself: domains come from the local DNS client cache only.
  It never creates its data folder: install.ps1 does, with an admin-only ACL.
  Keep this file ASCII-only (Windows PowerShell 5.1).
#>
param(
  [string]$Group = 'ClaudeEgressGuard',
  [string]$DataDir = (Join-Path $env:ProgramData 'ClaudeEgressGuard'),
  [string]$RangesFile = (Join-Path $PSScriptRoot 'anthropic-ranges.txt')
)
$ErrorActionPreference = 'Stop'
$LogPath  = Join-Path $DataDir 'blocked.jsonl'
$State    = Join-Path $DataDir 'blocklog.state'      # last processed event record id
$Filters  = Join-Path $DataDir 'filters.json'        # cached filter ids (per boot)
$MaxBytes = 5MB
$Utf8     = New-Object System.Text.UTF8Encoding($false)
$Inv      = [Globalization.CultureInfo]::InvariantCulture

function Get-AnthropicNets {
  # Anthropic prefixes from the copy of config\anthropic-ranges.txt next to this script.
  $nets = @()
  if (Test-Path $RangesFile) {
    $nets = @(Get-Content $RangesFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
  }
  if ($nets.Count -eq 0) { $nets = @('160.79.104.0/23', '2607:6bc0::/48', '2607:6bc0:11::/48') }
  return $nets
}

function Test-InNet([string]$Ip, [string]$Cidr) {
  # True when $Ip lies inside $Cidr (IPv4 or IPv6).
  $parts = $Cidr.Split('/'); $net = [Net.IPAddress]::Parse($parts[0]); $bits = [int]$parts[1]
  $addr = $null
  if (-not [Net.IPAddress]::TryParse($Ip, [ref]$addr)) { return $false }
  if ($addr.AddressFamily -ne $net.AddressFamily) { return $false }
  $a = $addr.GetAddressBytes(); $n = $net.GetAddressBytes()
  for ($i = 0; $i -lt $a.Length; $i++) {
    $take = [Math]::Max(0, [Math]::Min(8, $bits - 8 * $i))
    if ($take -eq 0) { break }
    $mask = (0xFF -shl (8 - $take)) -band 0xFF
    if (($a[$i] -band $mask) -ne ($n[$i] -band $mask)) { return $false }
  }
  return $true
}

function Get-NewEvents([long]$After) {
  # Outbound 5157 events after record id $After (first run: the last hour), oldest first.
  # Reads newest -> oldest and stops at the first already-processed (or too old) event, so a run
  # costs time proportional to the NEW events, not to the size of the Security log.
  $xp = "*[System[EventID=5157]] and *[EventData[Data[@Name='Direction']='%%14593']]"
  $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery('Security', [System.Diagnostics.Eventing.Reader.PathType]::LogName, $xp)
  $q.ReverseDirection = $true
  $cutoff = (Get-Date).AddHours(-1)
  $list = New-Object System.Collections.ArrayList
  $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q)
  try {
    while ($true) {
      $e = $reader.ReadEvent()
      if ($null -eq $e) { break }
      if (($After -gt 0 -and $e.RecordId -le $After) -or ($After -le 0 -and $e.TimeCreated -lt $cutoff)) { $e.Dispose(); break }
      [void]$list.Add($e)
    }
  } finally { $reader.Dispose() }
  $list.Reverse()
  return ,($list.ToArray())   # (a generic List here makes PowerShell 5.1 throw "argument type mismatch")
}

function Read-FilterMap {
  # Cached { ours: {id: rule name}, others: [id] } for this boot, or a fresh empty one.
  $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('o')
  if (Test-Path $Filters) {
    try {
      $c = [IO.File]::ReadAllText($Filters) | ConvertFrom-Json
      if ($c.boot -eq $boot) {
        $ours = @{}; foreach ($p in $c.ours.PSObject.Properties) { $ours[$p.Name] = [string]$p.Value }
        $others = @{}; foreach ($id in @($c.others)) { if ($id) { $others[[string]$id] = 1 } }
        return @{ boot = $boot; ours = $ours; others = $others; fresh = $false }
      }
    } catch {}
  }
  return @{ boot = $boot; ours = @{}; others = @{}; fresh = $false }
}

function Update-FilterMap($Map, [string[]]$Ids) {
  # Re-read the WFP filter list once and classify the given ids as ours (named "<Group> - ...") or not.
  $tmp = Join-Path $DataDir ("filters-" + [IO.Path]::GetRandomFileName() + ".xml")
  try {
    netsh wfp show filters file="$tmp" | Out-Null
    [xml]$x = [IO.File]::ReadAllText($tmp)
    foreach ($f in $x.wfpdiag.filters.item) {
      if ([string]$f.displayData.name -like "$Group - *") { $Map.ours[[string]$f.filterId] = [string]$f.displayData.name }
    }
    foreach ($id in $Ids) { if (-not $Map.ours.ContainsKey($id)) { $Map.others[$id] = 1 } }
    $Map.fresh = $true
    $json = @{ boot = $Map.boot; ours = $Map.ours; others = @($Map.others.Keys) } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText($Filters, $json, $Utf8)
    return $true
  } catch {
    return $false
  } finally {
    Remove-Item $tmp -ErrorAction SilentlyContinue
  }
}

function Convert-Events($Events, $Map) {
  # Keep only events raised by our filters and group them into records.
  $nets = Get-AnthropicNets
  $dns = @{}
  try {
    Get-DnsClientCache -ErrorAction Stop | ForEach-Object {
      if ($_.Data -and -not $dns.ContainsKey([string]$_.Data)) { $dns[[string]$_.Data] = ([string]$_.Entry).ToLower() }
    }
  } catch {}
  $groups = [ordered]@{}
  foreach ($ev in $Events) {
    $d = @{}
    foreach ($x in ([xml]$ev.ToXml()).Event.EventData.Data) { $d[$x.Name] = $x.'#text' }
    $fid = [string]$d['FilterRTID']
    if (-not $Map.ours.ContainsKey($fid)) { continue }
    $rule = $Map.ours[$fid]
    $proto = switch ($d['Protocol']) { '6' { 'tcp' } '17' { 'udp' } default { "proto$($d['Protocol'])" } }
    $exe = [string]$d['Application'] -replace '^\\device\\harddiskvolume\d+', ''
    $key = "$exe|$($d['DestAddress'])|$($d['DestPort'])|$proto"
    $t = $ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss', $Inv)
    if (-not $groups.Contains($key)) {
      $groups[$key] = [ordered]@{ ts = $t; last = $t; n = 0; kind = ''; proto = $proto; dst = $d['DestAddress'];
        port = [int]$d['DestPort']; domain = $null; domain_src = $null; proc = $null; exe = $exe; rule = $rule;
        pid = $d['ProcessID'] }
    }
    $g = $groups[$key]; $g.n++; $g.last = $t
  }
  foreach ($g in $groups.Values) {
    $isAnthropic = $false
    foreach ($c in $nets) { if (Test-InNet $g.dst $c) { $isAnthropic = $true; break } }
    if ($isAnthropic) { $g.kind = 'anthropic' }
    elseif ($g.rule -like '*Claude Code only local*') { $g.kind = 'claude' }
    else { $g.kind = 'other' }
    if ($dns.ContainsKey($g.dst)) { $g.domain = $dns[$g.dst]; $g.domain_src = 'dns' }
    $p = Get-Process -Id ([int]$g.pid) -ErrorAction SilentlyContinue
    if ($p) { $g.proc = "$($p.ProcessName):$($g.pid)" } else { $g.proc = "$(Split-Path -Leaf $g.exe):$($g.pid)" }
    $g.Remove('pid')
  }
  return @($groups.Values)
}

function Write-Records($Records) {
  # Append JSON lines (UTF-8 without BOM); rotate to .1 above $MaxBytes.
  if (-not $Records -or $Records.Count -eq 0) { return }
  if ((Test-Path $LogPath) -and (Get-Item $LogPath).Length -gt $MaxBytes) { Move-Item -Force $LogPath "$LogPath.1" }
  $text = ($Records | ForEach-Object { (New-Object PSObject -Property $_) | ConvertTo-Json -Compress }) -join "`n"
  [IO.File]::AppendAllText($LogPath, $text + "`n", $Utf8)
}

if (-not (Test-Path -LiteralPath $DataDir -PathType Container)) { exit 0 }   # not installed (or removed)
[long]$last = 0
if (Test-Path $State) { [long]::TryParse(([IO.File]::ReadAllText($State)).Trim(), [ref]$last) | Out-Null }
$newest = (Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction SilentlyContinue).RecordId
if ($newest -and $newest -lt $last) { $last = 0 }   # the log was cleared: start over
$map = Read-FilterMap
# Two passes 5 s apart: task instances do not stack, so pick up events raised while we run.
for ($round = 0; $round -lt 2; $round++) {
  $events = Get-NewEvents $last
  if ($events.Count -gt 0) {
    $ids = @($events | ForEach-Object { ([xml]$_.ToXml()).Event.EventData.Data | Where-Object { $_.Name -eq 'FilterRTID' } |
      ForEach-Object { [string]$_.'#text' } } | Sort-Object -Unique)
    $unknown = @($ids | Where-Object { -not $map.ours.ContainsKey($_) -and -not $map.others.ContainsKey($_) })
    if ($unknown.Count -gt 0 -and -not $map.fresh) {
      # cannot tell ours from others: leave this batch (and the state) for the next run
      if (-not (Update-FilterMap $map $unknown)) { exit 1 }
    } elseif ($unknown.Count -gt 0) { foreach ($id in $unknown) { $map.others[$id] = 1 } }
    Write-Records (Convert-Events $events $map)
    $last = $events[-1].RecordId
    [IO.File]::WriteAllText($State, [string]$last, $Utf8)
  }
  if ($round -eq 0) { Start-Sleep -Seconds 5 }
}
