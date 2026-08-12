Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$composer = Join-Path $PSScriptRoot 'Compose-ProfileSet.ps1'
$root = Join-Path (
    [System.IO.Path]::GetTempPath()) (
    'artifact-signing-profile-composition-' + [Guid]::NewGuid().ToString('N'))

function Assert-True([bool] $Condition, [string] $Message) {
    if (-not $Condition) {
        throw [System.InvalidOperationException]::new($Message)
    }
}

function Write-CanonicalAscii([string] $Path, [string] $Text) {
    [System.IO.File]::WriteAllBytes(
        $Path,
        [System.Text.Encoding]::ASCII.GetBytes($Text))
}

try {
    [System.IO.Directory]::CreateDirectory($root) | Out-Null
    $packageDirectory = Join-Path $root 'package'
    [System.IO.Directory]::CreateDirectory($packageDirectory) | Out-Null
    $assemblyPath = Join-Path $packageDirectory 'Example.Profile.dll'
    [byte[]] $assemblyBytes = [System.Text.Encoding]::ASCII.GetBytes('example-profile-assembly')
    [System.IO.File]::WriteAllBytes($assemblyPath, $assemblyBytes)
    $assemblySha256 = [System.Convert]::ToHexStringLower(
        [System.Security.Cryptography.SHA256]::HashData($assemblyBytes))
    $manifestPath = Join-Path $packageDirectory 'profile-package.txt'
    $outputDirectory = Join-Path $root 'out'
    Write-CanonicalAscii $manifestPath (
        "Format=ArtifactSigningProfilePackageV1`n" +
        "PackageId=Example.Profile`n" +
        "PackageVersion=1.0.0`n" +
        "AssemblyFile=Example.Profile.dll`n" +
        "AssemblySha256=$assemblySha256`n" +
        "Profile=ExampleEndpointBundleV1|2|ArtifactSigning.TestProfile.ExampleEndpointBundleV1`n")

    & $composer -Manifest $manifestPath -OutputDirectory $outputDirectory
    $sourcePath = Join-Path $outputDirectory 'InstalledProfileSet.g.cs'
    $propsPath = Join-Path $outputDirectory 'ArtifactSigning.ProfileComposition.props'
    $lockPath = Join-Path $outputDirectory 'profile-set.lock'
    Assert-True ([System.IO.File]::Exists($sourcePath)) 'Composer did not generate source.'
    Assert-True ([System.IO.File]::Exists($propsPath)) 'Composer did not generate props.'
    Assert-True ([System.IO.File]::Exists($lockPath)) 'Composer did not generate lock data.'
    [byte[]] $lockBytes = [System.IO.File]::ReadAllBytes($lockPath)
    Assert-True ($lockBytes[$lockBytes.Length - 1] -eq 10) 'Lock output did not end in LF.'
    Assert-True (-not ($lockBytes -contains 13)) 'Lock output contains CR.'
    Assert-True (
        ([System.Text.Encoding]::ASCII.GetString(
            [System.IO.File]::ReadAllBytes($sourcePath))).Contains(
            'global::ArtifactSigning.TestProfile.ExampleEndpointBundleV1.Instance',
            [System.StringComparison]::Ordinal)) 'Generated source did not bind the declared static profile.'
    $propsText = [System.Text.Encoding]::ASCII.GetString(
        [System.IO.File]::ReadAllBytes($propsPath))
    Assert-True (
        $propsText.Contains(
            '<Reference Include="Example.Profile">',
            [System.StringComparison]::Ordinal) -and
        -not $propsText.Contains(
            'ProjectReference',
            [System.StringComparison]::Ordinal)) `
        'Generated composition did not reference the exact package assembly.'

    Write-CanonicalAscii $manifestPath (
        "Format=ArtifactSigningProfilePackageV1`n" +
        "PackageId=Example.Profile`n" +
        "PackageVersion=1.0.0`n" +
        "AssemblyFile=Example.Profile.dll`n" +
        "AssemblySha256=$('0' * 64)`n" +
        "Profile=ExampleEndpointBundleV1|2|ArtifactSigning.TestProfile.ExampleEndpointBundleV1`n")
    $rejected = $false
    try {
        & $composer -Manifest $manifestPath -OutputDirectory $outputDirectory
    }
    catch [System.ArgumentException] {
        $rejected = $true
    }

    Assert-True $rejected 'Composer accepted an assembly digest mismatch.'

    Write-CanonicalAscii $manifestPath (
        "Format=ArtifactSigningProfilePackageV1`n" +
        "PackageId=Example.Profile`n" +
        "PackageVersion=1.0.0`n" +
        "AssemblyFile=Example.Profile.dll`n" +
        "AssemblySha256=$assemblySha256`n" +
        "Profile=ExampleEndpointBundleV1|2|ArtifactSigning.TestProfile.ExampleEndpointBundleV1`n")
    Write-CanonicalAscii (Join-Path $packageDirectory 'unexpected.txt') "unexpected`n"
    $rejected = $false
    try {
        & $composer -Manifest $manifestPath -OutputDirectory $outputDirectory
    }
    catch [System.ArgumentException] {
        $rejected = $true
    }

    Assert-True $rejected 'Composer accepted an unexpected package entry.'
}
finally {
    if ([System.IO.Directory]::Exists($root)) {
        [System.IO.Directory]::Delete($root, $true)
    }
}
