[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]] $Manifest,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ProfilePackageAbiVersion = 1
$script:DescriptorFormat = 'ArtifactSigningProfilePackageDescriptorV1'
$script:PackageFormat = 'ArtifactSigningProfilePackageReleaseV1'
$script:PackageSetFormat = 'ArtifactSigningProfilePackageSetV1'
$script:ProfileFormat = 'ArtifactSigningProfilePackageProfileV1'

function Fail([string] $Message) {
    throw [System.ArgumentException]::new($Message)
}

function Test-SafeIdentifier([string] $Value) {
    return $Value -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
}

function Test-LeafFileName([string] $Value) {
    return $Value -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' -and
        -not $Value.EndsWith('.', [System.StringComparison]::Ordinal)
}

function Test-LowerSha256([string] $Value) {
    return $Value -match '^[0-9a-f]{64}$'
}

function Test-CanonicalSemanticVersion([string] $Value) {
    return $Value -match '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$'
}

function Get-Sha256([byte[]] $Bytes) {
    return [System.Convert]::ToHexStringLower(
        [System.Security.Cryptography.SHA256]::HashData($Bytes))
}

function Get-AsciiSha256([string] $Value) {
    if ($Value -match '[^\x00-\x7F]') {
        Fail 'Canonical profile composition text must be ASCII.'
    }

    return Get-Sha256 ([System.Text.Encoding]::ASCII.GetBytes($Value))
}

function Get-OrdinalProfiles([object[]] $Profiles) {
    [object[]] $ordered = @($Profiles)
    [System.Array]::Sort(
        $ordered,
        [System.Comparison[object]]{
            param($left, $right)
            $idComparison = [string]::Compare(
                $left.ProfileId,
                $right.ProfileId,
                [System.StringComparison]::Ordinal)
            if ($idComparison -ne 0) {
                return $idComparison
            }

            return $left.ProfileVersion.CompareTo($right.ProfileVersion)
        })
    return $ordered
}

function Get-OrdinalPackages([object[]] $Packages) {
    [object[]] $ordered = @($Packages)
    [System.Array]::Sort(
        $ordered,
        [System.Comparison[object]]{
            param($left, $right)
            return [string]::Compare(
                $left.PackageId,
                $right.PackageId,
                [System.StringComparison]::Ordinal)
        })
    return $ordered
}

function Get-CanonicalDescriptorSha256($Package) {
    $builder = [System.Text.StringBuilder]::new()
    [void] $builder.Append($script:DescriptorFormat).Append("`n")
    [void] $builder.Append('AbiVersion=').Append($script:ProfilePackageAbiVersion).Append("`n")
    [void] $builder.Append('PackageId=').Append($Package.PackageId).Append("`n")
    [void] $builder.Append('PackageVersion=').Append($Package.PackageVersion).Append("`n")
    [void] $builder.Append('AssemblySha256=').Append($Package.AssemblySha256).Append("`n")
    foreach ($profile in Get-OrdinalProfiles @($Package.Profiles)) {
        [void] $builder.Append('Profile=').Append($profile.ProfileId).
            Append('@').Append($profile.ProfileVersion).Append("`n")
    }

    return Get-AsciiSha256 $builder.ToString()
}

function Get-CanonicalPackageSha256([string] $DescriptorSha256, [string] $AssemblySha256) {
    return Get-AsciiSha256 (
        $script:PackageFormat + "`n" +
        'DescriptorSha256=' + $DescriptorSha256 + "`n" +
        'AssemblySha256=' + $AssemblySha256 + "`n")
}

function Get-CanonicalProfileSha256($Package, $Profile) {
    return Get-AsciiSha256 (
        $script:ProfileFormat + "`n" +
        'PackageSha256=' + $Package.PackageSha256 + "`n" +
        'ProfileId=' + $Profile.ProfileId + "`n" +
        'ProfileVersion=' + $Profile.ProfileVersion + "`n")
}

function Get-CanonicalPackageSetSha256([object[]] $Packages) {
    $builder = [System.Text.StringBuilder]::new()
    [void] $builder.Append($script:PackageSetFormat).Append("`n")
    [void] $builder.Append('AbiVersion=').Append($script:ProfilePackageAbiVersion).Append("`n")
    foreach ($package in Get-OrdinalPackages $Packages) {
        [void] $builder.Append('PackageId=').Append($package.PackageId).Append("`n")
        [void] $builder.Append('PackageVersion=').Append($package.PackageVersion).Append("`n")
        [void] $builder.Append('PackageSha256=').Append($package.PackageSha256).Append("`n")
        [void] $builder.Append('AssemblySha256=').Append($package.AssemblySha256).Append("`n")
        [void] $builder.Append('DescriptorSha256=').Append($package.DescriptorSha256).Append("`n")
    }

    return Get-AsciiSha256 $builder.ToString()
}

function Read-CanonicalManifest([string] $ManifestPath) {
    $resolvedManifest = [System.IO.Path]::GetFullPath($ManifestPath)
    if (-not [System.IO.File]::Exists($resolvedManifest)) {
        Fail 'Profile composition input does not exist.'
    }
    if ([System.IO.Path]::GetFileName($resolvedManifest) -cne
        'profile-package.txt') {
        Fail 'Profile composition input names are invalid.'
    }

    $manifestItem = Get-Item -LiteralPath $resolvedManifest -Force
    if ($manifestItem.PSIsContainer -or $manifestItem.LinkType -or
        ($manifestItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail 'Profile composition input must be a direct regular file.'
    }

    [byte[]] $bytes = [System.IO.File]::ReadAllBytes($resolvedManifest)
    if ($bytes.Length -eq 0 -or $bytes[$bytes.Length - 1] -ne 10 -or
        $bytes -contains 13 -or $bytes | Where-Object { $_ -gt 127 }) {
        Fail 'Profile package manifest must be canonical ASCII with LF line endings and one trailing LF.'
    }

    $text = [System.Text.Encoding]::ASCII.GetString($bytes)
    [string[]] $lines = $text.Split("`n", [System.StringSplitOptions]::None)
    if ($lines[$lines.Length - 1] -ne [string]::Empty) {
        Fail 'Profile package manifest has no canonical trailing LF.'
    }

    $lines = $lines[0..($lines.Length - 2)]
    if ($lines.Length -lt 6) {
        Fail 'Profile package manifest is incomplete.'
    }

    $expected = @('Format', 'PackageId', 'PackageVersion', 'AssemblyFile', 'AssemblySha256')
    $values = [ordered]@{}
    for ($index = 0; $index -lt $expected.Length; $index++) {
        [string] $line = $lines[$index]
        [string] $prefix = $expected[$index] + '='
        if (-not $line.StartsWith($prefix, [System.StringComparison]::Ordinal) -or
            $line.IndexOf('=', $prefix.Length) -ge 0) {
            Fail 'Profile package manifest contains an invalid or out-of-order fixed field.'
        }

        $values[$expected[$index]] = $line.Substring($prefix.Length)
    }

    if ($values.Format -ne 'ArtifactSigningProfilePackageV1' -or
        -not (Test-SafeIdentifier $values.PackageId) -or
        -not (Test-CanonicalSemanticVersion $values.PackageVersion) -or
        -not (Test-LeafFileName $values.AssemblyFile) -or
        -not (Test-LowerSha256 $values.AssemblySha256)) {
        Fail 'Profile package manifest contains an invalid fixed field value.'
    }

    $profiles = [System.Collections.Generic.List[object]]::new()
    $identities = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $types = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    for ($index = $expected.Length; $index -lt $lines.Length; $index++) {
        [string] $line = $lines[$index]
        if (-not $line.StartsWith('Profile=', [System.StringComparison]::Ordinal)) {
            Fail 'Profile package manifest contains an unknown field.'
        }

        [string[]] $parts = $line.Substring('Profile='.Length).Split('|', [System.StringSplitOptions]::None)
        if ($parts.Length -ne 3 -or
            -not (Test-SafeIdentifier $parts[0]) -or
            $parts[1] -notmatch '^[1-9][0-9]{0,9}$' -or
            $parts[2] -notmatch '^([A-Za-z_][A-Za-z0-9_]*\.)+[A-Za-z_][A-Za-z0-9_]*$') {
            Fail 'Profile package manifest contains an invalid profile declaration.'
        }

        [int] $profileVersion = 0
        if (-not [int]::TryParse(
                $parts[1],
                [System.Globalization.NumberStyles]::None,
                [System.Globalization.CultureInfo]::InvariantCulture,
                [ref] $profileVersion)) {
            Fail 'Profile package manifest contains an invalid profile version.'
        }

        $identity = $parts[0] + '|' + $profileVersion
        if (-not $identities.Add($identity) -or -not $types.Add($parts[2])) {
            Fail 'Profile package manifest contains duplicate profile identity or type.'
        }

        [void] $profiles.Add([pscustomobject]@{
                ProfileId = $parts[0]
                ProfileVersion = $profileVersion
                TypeName = $parts[2]
                ProfileSha256 = ''
            })
    }

    if ($profiles.Count -eq 0) {
        Fail 'Profile package manifest must declare at least one profile.'
    }

    $assemblyPath = Join-Path ([System.IO.Path]::GetDirectoryName($resolvedManifest)) $values.AssemblyFile
    if (-not [System.IO.File]::Exists($assemblyPath)) {
        Fail 'Profile package assembly is missing.'
    }

    $assemblyItem = Get-Item -LiteralPath $assemblyPath -Force
    if ($assemblyItem.LinkType -or $assemblyItem.PSIsContainer -or
        ($assemblyItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail 'Profile package assembly must be a direct regular file.'
    }

    $packageEntries = @(Get-ChildItem -LiteralPath $manifestItem.DirectoryName -Force)
    if ($packageEntries.Count -ne 2 -or
        @($packageEntries | Where-Object {
                $_.PSIsContainer -or $_.LinkType -or
                ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($_.Name -cne 'profile-package.txt' -and
                    $_.Name -cne $values.AssemblyFile)
            }).Count -ne 0) {
        Fail 'Profile package directory must contain only its manifest and declared assembly.'
    }

    [byte[]] $assemblyBytes = [System.IO.File]::ReadAllBytes($assemblyPath)
    $actualAssemblySha256 = Get-Sha256 $assemblyBytes
    if (-not [System.Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
            [System.Text.Encoding]::ASCII.GetBytes($values.AssemblySha256),
            [System.Text.Encoding]::ASCII.GetBytes($actualAssemblySha256))) {
        Fail 'Profile package assembly digest does not match the manifest.'
    }

    return [pscustomobject]@{
        PackageId = $values.PackageId
        PackageVersion = $values.PackageVersion
        AssemblyFile = $values.AssemblyFile
        AssemblyPath = [System.IO.Path]::GetFullPath($assemblyPath)
        AssemblyBytes = $assemblyBytes
        CompositionAssemblyPath = ''
        AssemblySha256 = $values.AssemblySha256
        Profiles = @($profiles)
        DescriptorSha256 = ''
        PackageSha256 = ''
    }
}

function Escape-CSharpString([string] $Value) {
    return $Value.Replace('\\', '\\\\').Replace('"', '\\"')
}

function Write-CanonicalAsciiFile([string] $Path, [string] $Content) {
    if ($Content -notmatch "`n$" -or $Content.Contains("`r", [System.StringComparison]::Ordinal) -or
        $Content -match '[^\x00-\x7F]') {
        Fail 'Generated profile composition output was not canonical ASCII LF text.'
    }

    [System.IO.File]::WriteAllBytes(
        $Path,
        [System.Text.Encoding]::ASCII.GetBytes($Content))
}

if ($Manifest.Count -eq 0) {
    Fail 'Profile composition requires at least one package manifest.'
}

$output = [System.IO.Path]::GetFullPath($OutputDirectory)
[System.IO.Directory]::CreateDirectory($output) | Out-Null
$packages = [System.Collections.Generic.List[object]]::new()
for ($index = 0; $index -lt $Manifest.Count; $index++) {
    $package = Read-CanonicalManifest $Manifest[$index]
    [void] $packages.Add($package)
}

$packageIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
$assemblyFiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($package in $packages) {
    if (-not $packageIds.Add($package.PackageId) -or
        -not $assemblyFiles.Add($package.AssemblyFile)) {
        Fail 'Profile composition contains a duplicate package or assembly identity.'
    }

    $package.DescriptorSha256 = Get-CanonicalDescriptorSha256 $package
    $package.PackageSha256 = Get-CanonicalPackageSha256 $package.DescriptorSha256 $package.AssemblySha256
    foreach ($profile in $package.Profiles) {
        $profile.ProfileSha256 = Get-CanonicalProfileSha256 $package $profile
    }

    $compositionPackageDirectory = Join-Path $output (
        'packages' + [System.IO.Path]::DirectorySeparatorChar + $package.PackageId)
    [System.IO.Directory]::CreateDirectory($compositionPackageDirectory) | Out-Null
    $package.CompositionAssemblyPath = Join-Path `
        $compositionPackageDirectory $package.AssemblyFile
    [System.IO.File]::WriteAllBytes(
        $package.CompositionAssemblyPath,
        $package.AssemblyBytes)
}

$orderedPackages = Get-OrdinalPackages @($packages)
$packageSetSha256 = Get-CanonicalPackageSetSha256 $orderedPackages
$source = [System.Text.StringBuilder]::new()
[void] $source.Append("// <auto-generated />`n")
[void] $source.Append("using ArtifactSigning.Profiles;`n`n")
[void] $source.Append("namespace ArtifactSigning.Composition;`n`n")
[void] $source.Append("internal static partial class InstalledProfileSet`n{`n")
[void] $source.Append("    static partial void AddPackages(List<ISigningProfilePackage> packages)`n    {`n")
foreach ($package in $orderedPackages) {
    [void] $source.Append("        packages.Add(new CompiledSigningProfilePackage(`n")
    [void] $source.Append("            new SigningProfilePackageDescriptor(`n")
    [void] $source.Append("                $script:ProfilePackageAbiVersion,`n")
    [void] $source.Append('                "').Append((Escape-CSharpString $package.PackageId)).Append('",').Append("`n")
    [void] $source.Append('                "').Append((Escape-CSharpString $package.PackageVersion)).Append('",').Append("`n")
    [void] $source.Append('                "').Append($package.PackageSha256).Append('",').Append("`n")
    [void] $source.Append('                "').Append($package.AssemblySha256).Append('",').Append("`n")
    [void] $source.Append('                "').Append($package.DescriptorSha256).Append('",').Append("`n")
    [void] $source.Append("                [`n")
    foreach ($profile in Get-OrdinalProfiles @($package.Profiles)) {
        [void] $source.Append('                    new SigningProfileIdentity("').
            Append((Escape-CSharpString $profile.ProfileId)).Append('", ').
            Append($profile.ProfileVersion).Append('),').Append("`n")
    }

    [void] $source.Append("                ]),`n            [`n")
    foreach ($profile in Get-OrdinalProfiles @($package.Profiles)) {
        [void] $source.Append("                global::").Append($profile.TypeName).Append(".Instance,`n")
    }

    [void] $source.Append("            ]));`n")
}

[void] $source.Append("    }`n}`n")
Write-CanonicalAsciiFile (Join-Path $output 'InstalledProfileSet.g.cs') $source.ToString()

$props = [System.Text.StringBuilder]::new()
[void] $props.Append("<Project>`n")
[void] $props.Append('  <ItemGroup Condition="''$(MSBuildProjectName)'' == ''ArtifactSigning.Gateway'' Or ''$(MSBuildProjectName)'' == ''ArtifactSigning.Worker'' Or ''$(MSBuildProjectName)'' == ''ArtifactSigning.Cli''">').Append("`n")
foreach ($package in $orderedPackages) {
    $escapedAssemblyPath = [System.Security.SecurityElement]::Escape(
        $package.CompositionAssemblyPath)
    $escapedPackageId = [System.Security.SecurityElement]::Escape($package.PackageId)
    [void] $props.Append('    <Reference Include="').Append($escapedPackageId).Append('">').Append("`n")
    [void] $props.Append('      <HintPath>').Append($escapedAssemblyPath).Append('</HintPath>').Append("`n")
    [void] $props.Append("      <Private>true</Private>`n")
    [void] $props.Append("    </Reference>`n")
}

[void] $props.Append('    <Compile Include="$(MSBuildThisFileDirectory)InstalledProfileSet.g.cs" Link="Composition\InstalledProfileSet.g.cs" />').Append("`n")
[void] $props.Append("  </ItemGroup>`n</Project>`n")
Write-CanonicalAsciiFile (Join-Path $output 'ArtifactSigning.ProfileComposition.props') $props.ToString()

$lock = [System.Text.StringBuilder]::new()
[void] $lock.Append("Format=ArtifactSigningProfileSetLockV1`n")
[void] $lock.Append('AbiVersion=').Append($script:ProfilePackageAbiVersion).Append("`n")
[void] $lock.Append('PackageSetSha256=').Append($packageSetSha256).Append("`n")
foreach ($package in $orderedPackages) {
    [void] $lock.Append('Package=').Append($package.PackageId).Append('|').
        Append($package.PackageVersion).Append('|').Append($package.PackageSha256).Append('|').
        Append($package.AssemblySha256).Append('|').Append($package.DescriptorSha256).Append("`n")
    foreach ($profile in Get-OrdinalProfiles @($package.Profiles)) {
        [void] $lock.Append('Profile=').Append($package.PackageId).Append('|').
            Append($profile.ProfileId).Append('|').Append($profile.ProfileVersion).Append('|').
            Append($profile.ProfileSha256).Append("`n")
    }
}

Write-CanonicalAsciiFile (Join-Path $output 'profile-set.lock') $lock.ToString()
