<#
.SYNOPSIS
  claude-egress-guard - Windows uninstaller (elevated PowerShell).
.DESCRIPTION
  Removes the firewall rule group and restores (or removes) the managed settings written by
  install.ps1. Add -RemoveUserEnv to also delete NODE_USE_ENV_PROXY / HTTP(S)_PROXY / NO_PROXY
  from the user environment.
#>
[CmdletBinding()]
param([switch]$RemoveUserEnv)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
Assert-CegAdmin

Get-NetFirewallRule -Group $CegGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Write-Host "removed firewall group $CegGroup"

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
