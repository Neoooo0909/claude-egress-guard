<#
.SYNOPSIS
  claude-egress-guard - show what the firewall rules blocked (reads the block log).
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File "$env:ProgramFiles\ClaudeEgressGuard\blocked.ps1"
.EXAMPLE
  ... blocked.ps1 -Days 3 -Tail 30
#>
param([int]$Days = 1, [int]$Tail = 10, [switch]$Raw)
$LogPath = Join-Path $env:ProgramData 'ClaudeEgressGuard\blocked.jsonl'
$Kind = @{ anthropic = 'Anthropic'; claude = 'claude.exe direct'; other = 'other' }
if (-not (Test-Path $LogPath)) { "no block log yet ($LogPath): not installed, or nothing was blocked."; exit 0 }
$since = (Get-Date).Date.AddDays(1 - [Math]::Max($Days, 1)).ToString('yyyy-MM-dd')
$recs = @(foreach ($p in @("$LogPath.1", $LogPath)) {
  if (Test-Path $p) { Get-Content -Encoding UTF8 $p | ForEach-Object { try { $_ | ConvertFrom-Json } catch {} } }
}) | Where-Object { $_.ts -ge $since } | Sort-Object ts
if ($Raw) { $recs | ForEach-Object { $_ | ConvertTo-Json -Compress }; exit 0 }
$span = if ($Days -le 1) { 'today' } else { "last $Days days" }
$total = ($recs | Measure-Object -Property n -Sum).Sum
$kinds = $recs | Group-Object kind | ForEach-Object { "$($Kind[$_.Name]) $(($_.Group | Measure-Object -Property n -Sum).Sum)" }
"${span}: $([int]$total) connections blocked ($($kinds -join ', '))"
if (-not $recs) { exit 0 }
""
"top sources (target | program | count | last seen):"
$recs | Group-Object { "$(if ($_.domain) { $_.domain } else { $_.dst })|$(($_.proc -split ':')[0])" } |
  ForEach-Object { [pscustomobject]@{ Key = $_.Name; N = ($_.Group | Measure-Object -Property n -Sum).Sum;
    Last = ($_.Group | Sort-Object last | Select-Object -Last 1).last; Anth = ($_.Group.kind -contains 'anthropic') } } |
  Sort-Object N -Descending | Select-Object -First 15 | ForEach-Object {
    $k = $_.Key.Split('|'); $flag = if ($_.Anth) { '  ! Anthropic' } else { '' }
    "  $($k[0]) | $($k[1]) | $($_.N) | $($_.Last.Substring(5))$flag" }
""
"last $Tail records:"
$recs | Select-Object -Last $Tail | ForEach-Object {
  "  $($_.ts.Substring(5)) $($Kind[$_.kind]) $($_.proto) $($_.dst):$($_.port) $($_.domain) | $($_.proc) x$($_.n)  <- $($_.exe)" }
