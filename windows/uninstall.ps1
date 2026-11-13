<#
.SYNOPSIS
  claude-egress-guard - Windows uninstaller (elevated PowerShell).
.DESCRIPTION
  Removes the firewall rule group and the block log (scheduled task, collector, log; the audit
  setting and the Security log size are put back as recorded at the first install), and restores
  (or removes) the managed settings written by install.ps1. Add -RemoveUserEnv to also delete NODE_USE_ENV_PROXY / HTTP(S)_PROXY / NO_PROXY
  from the user environment.
#>
[CmdletBinding()]
param([switch]$RemoveUserEnv)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
Assert-CegAdmin

Get-NetFirewallRule -Group $CegGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Write-Host "removed firewall group $CegGroup"

# Block log: stop the task, put the audit setting / Security log size back, remove files
Stop-ScheduledTask -TaskName $CegBlockTask -ErrorAction SilentlyContinue   # a running instance keeps files open
Unregister-ScheduledTask -TaskName $CegBlockTask -Confirm:$false -ErrorAction SilentlyContinue
if (Test-Path $CegAuditOrig) {
  $orig = 0; [int]::TryParse((Get-Content $CegAuditOrig -Raw).Trim(), [ref]$orig) | Out-Null
  if (-not ($orig -band 2)) { auditpol /set /subcategory:$CegAuditGuid /failure:disable | Out-Null }
}
if (Test-Path $CegSecLogOrig) {
  $size = [long]0; [long]::TryParse((Get-Content $CegSecLogOrig -Raw).Trim(), [ref]$size) | Out-Null
  # only undo OUR change: if someone set another size since, leave it alone
  if ($size -gt 0 -and $size -lt 128MB -and (Get-WinEvent -ListLog Security).MaximumSizeInBytes -eq 128MB) {
    wevtutil sl Security /ms:$size
    if ($LASTEXITCODE -ne 0) { Write-Warning "could not shrink the Security log back to $size bytes" }
  }
}
Remove-CegDirectory $CegToolDir
Remove-CegDirectory $CegDataDir
Write-Host 'removed block log (task, files; audit setting and Security log size restored)'

# Put the managed settings back exactly as they were before the FIRST install
if (Test-Path $CegCreatedMarker) {
  Remove-Item $CegManagedFile -Force -ErrorAction SilentlyContinue
  Remove-Item $CegCreatedMarker -Force
  Write-Host "removed $CegManagedFile (it did not exist before install)"
} elseif (Test-Path $CegOrigFile) {
  Move-Item $CegOrigFile $CegManagedFile -Force
  Write-Host "restored $CegManagedFile to its pre-install content"
}
# Remove the folder if install.ps1 left it empty
if ((Test-Path $CegManagedDir) -and -not (Get-ChildItem $CegManagedDir -Force)) { Remove-Item $CegManagedDir }

if ($RemoveUserEnv) {
  foreach ($n in 'NODE_USE_ENV_PROXY', 'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY') {
    [Environment]::SetEnvironmentVariable($n, $null, 'User')
  }
  Write-Host 'removed user environment variables'
}
