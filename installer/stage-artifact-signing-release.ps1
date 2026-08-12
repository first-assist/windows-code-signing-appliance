[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $Source,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string] $ExpectedReleaseHash
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ArtifactSigning.Installer.ps1')

$phase = 'HostValidation'
try {
Assert-ArtifactSigningInstallerHost
$paths = Get-ArtifactSigningInstallerPaths
$phase = 'SourceValidation'
$sourceRoot = [IO.Path]::GetFullPath($Source)
Read-ArtifactSigningReleaseInventory `
    -PackageRoot $sourceRoot `
    -ExpectedInventorySha256 $ExpectedReleaseHash | Out-Null
$phase = 'GenerationValidation'
if (Test-Path -LiteralPath $paths.StagingRoot) {
    throw 'An installer staging generation already exists.'
}

$phase = 'StagingCopy'
[IO.Directory]::CreateDirectory($paths.ControlRoot) | Out-Null
Copy-Item -LiteralPath $sourceRoot `
    -Destination $paths.StagingRoot -Recurse
$builtIn = Get-ArtifactSigningBuiltInSids
$phase = 'ControlAcl'
Set-ArtifactSigningExactAcl -Path $paths.ControlRoot `
    -FullControl @($builtIn.System, $builtIn.Administrators) `
    -ReadAndExecute @() -Directory $true
Set-ArtifactSigningExactAcl -Path $paths.StagingRoot `
    -FullControl @($builtIn.System, $builtIn.Administrators) `
    -ReadAndExecute @() -Directory $true
$phase = 'StagingTreeAcl'
Get-ChildItem -LiteralPath $paths.StagingRoot -Directory -Recurse -Force |
    ForEach-Object {
        Set-ArtifactSigningExactAcl -Path $_.FullName `
            -FullControl @($builtIn.System, $builtIn.Administrators) `
            -ReadAndExecute @() -Directory $true
    }
Get-ChildItem -LiteralPath $paths.StagingRoot -File -Recurse -Force |
    ForEach-Object {
        Set-ArtifactSigningExactAcl -Path $_.FullName `
            -FullControl @($builtIn.System, $builtIn.Administrators) `
            -ReadAndExecute @() -Directory $false
    }
$phase = 'StagedInventory'
Read-ArtifactSigningReleaseInventory `
    -PackageRoot $paths.StagingRoot `
    -ExpectedInventorySha256 $ExpectedReleaseHash | Out-Null

Write-Output 'STAGE_OK'
}
catch {
    throw "ArtifactSigningStageFailed:$phase"
}
