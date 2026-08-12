[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ArtifactSigning.Installer.ps1')

Assert-ArtifactSigningInstallerHost
$paths = Get-ArtifactSigningInstallerPaths
if (-not $PSCmdlet.ShouldProcess(
        $paths.InstallRoot,
        'Remove services, firewall rules, Event Log sources, and service bytes; preserve all keys and ProgramData state')) {
    return
}

Remove-ArtifactSigningFirewallPolicy
Remove-ArtifactSigningAzureArcIdentityAccess
Remove-ArtifactSigningServiceDefinitions
Write-ArtifactSigningInstallerEvent `
    -EntryType Information -EventId 1004 `
    -ResultCode UNINSTALL_OK
Unregister-ArtifactSigningEventSources
if (Test-Path -LiteralPath $paths.InstallRoot) {
    Remove-Item -LiteralPath $paths.InstallRoot -Recurse -Force
}

Write-Output 'UNINSTALL_OK_KEYS_AND_STATE_PRESERVED'
