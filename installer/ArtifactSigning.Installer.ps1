Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ArtifactSigningInstallerVersion = '0.4.1'
$script:GatewayServiceName = 'ArtifactSigningGateway'
$script:WorkerServiceName = 'ArtifactSigningWorker'
$script:ReleaseInventoryName = 'release-inventory.txt'
$script:DeploymentName = 'deployment.txt'
$script:ExpectedDeploymentV2Keys = @(
    'Format',
    'ReleaseVersion',
    'SourceCommit',
    'InstallerVersion',
    'GatewayVersion',
    'WorkerVersion',
    'CliVersion',
    'ProfileSetSha256',
    'GatewayListenAddress',
    'GatewayListenPort',
    'GatewayIngressRemoteAddresses',
    'TimestampRelayAddress',
    'TimestampRelayPort',
    'CertificateStatusRemoteAddresses',
    'TimeServerAddresses',
    'GatewayTlsCertificateThumbprint',
    'ReceiptCertificateThumbprint',
    'AuthenticodeCertificateThumbprint',
    'SignToolPath',
    'SignToolSha256',
    'SignToolFileVersion'
)
$script:ExpectedDeploymentV3Keys = @(
    $script:ExpectedDeploymentV2Keys
    'SigningProvider'
    'DnsServerAddresses'
    'ManagedEgressPolicy'
    'MicrosoftArtifactSigningRegion'
    'MicrosoftArtifactSigningAccountName'
    'MicrosoftArtifactSigningCertificateProfileName'
    'MicrosoftArtifactSigningDlibSha256'
    'MicrosoftArtifactSigningDlibFileVersion'
    'MicrosoftArtifactSigningClientToolsInventorySha256'
    'MicrosoftArtifactSigningRuntimeMajor'
    'MicrosoftArtifactSigningExpectedPublisherSubjectNameSha256'
    'MicrosoftArtifactSigningRequiredPublisherEnhancedKeyUsageOid'
    'MicrosoftArtifactSigningTrustedPublisherRootThumbprints'
    'MicrosoftArtifactSigningSignToolTimeoutSeconds'
    'MicrosoftArtifactSigningAuthenticodeRevocationPolicy'
)
$script:ExpectedDeploymentKeys = @(
    $script:ExpectedDeploymentV2Keys +
    $script:ExpectedDeploymentV3Keys |
        Sort-Object -Unique
)
$script:ArtifactSigningRollbackLegacyInstallerVersions = @(
    '0.4.0'
    '0.3.2'
)
$script:MicrosoftCertificateStatusDynamicKeywords = @(
    @{
        Id = '{06D76082-F594-446B-A03B-FEC14ACDEC52}'
        Fqdn = 'www.microsoft.com'
    },
    @{
        Id = '{6FE8BFF5-8A0B-4E71-BD71-77D7D5426571}'
        Fqdn = 'oneocsp.microsoft.com'
    }
)

function Assert-ArtifactSigningInstallerHost {
    if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) {
        throw 'The Artifact Signing installer is Windows-only.'
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'The Artifact Signing installer requires elevation.'
    }
}

function Get-ArtifactSigningInstallerPaths {
    $programFiles = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::ProgramFiles)
    $programData = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::CommonApplicationData)
    if (-not (Test-ArtifactSigningFullyQualifiedPath -Path $programFiles) -or
        -not (Test-ArtifactSigningFullyQualifiedPath -Path $programData)) {
        throw 'Protected Windows installation roots are unavailable.'
    }

    $installRoot = Join-Path $programFiles 'ArtifactSigning'
    $stateRoot = Join-Path $programData 'ArtifactSigning'
    $controlRoot = Join-Path $programData 'ArtifactSigningInstaller'
    [pscustomobject]@{
        InstallRoot = $installRoot
        GatewayRoot = Join-Path $installRoot 'Gateway'
        WorkerRoot = Join-Path $installRoot 'Worker'
        InstallerRoot = Join-Path $installRoot 'Installer'
        StateRoot = $stateRoot
        ControlRoot = $controlRoot
        StagingRoot = Join-Path $controlRoot 'staging'
        RollbackRoot = Join-Path $controlRoot 'rollback'
        InstalledInventory = Join-Path $controlRoot 'installed-inventory.txt'
        InstalledDeployment = Join-Path $controlRoot 'installed-deployment.txt'
        InstalledReleaseDigest = Join-Path $controlRoot 'installed-release.sha256'
        InstalledProfileSetLock = Join-Path $controlRoot 'installed-profile-set.lock'
    }
}

function Test-ArtifactSigningFullyQualifiedPath {
    param([Parameter(Mandatory)][string] $Path)

    if ([string]::IsNullOrEmpty($Path) -or
        -not [IO.Path]::IsPathRooted($Path)) {
        return $false
    }

    try {
        [IO.Path]::GetFullPath($Path) | Out-Null
    }
    catch {
        return $false
    }

    if ([IO.Path]::DirectorySeparatorChar -ne '\') {
        return $Path[0] -eq [IO.Path]::DirectorySeparatorChar
    }

    if ($Path -cmatch '^[A-Za-z]:[\\/]') {
        return $true
    }

    return $Path -cmatch '^\\\\(?![?.]\\)[^\\]+\\[^\\]+(?:\\|$)'
}

function Test-ArtifactSigningWindowsDeploymentPath {
    param([Parameter(Mandatory)][string] $Path)

    if ([string]::IsNullOrEmpty($Path) -or
        $Path -cnotmatch '^[A-Za-z]:\\[^\\/:*?"<>|]+(?:\\[^\\/:*?"<>|]+)*$') {
        return $false
    }

    $segments = $Path.Substring(3).Split([char]92)
    return -not @($segments | Where-Object {
            $_ -in @('.', '..') -or
            $_.EndsWith(' ', [StringComparison]::Ordinal) -or
            $_.EndsWith('.', [StringComparison]::Ordinal)
        })
}

function Get-ArtifactSigningApplicationPath {
    param([Parameter(Mandatory)][string] $Name)

    if ($Name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') {
        throw 'A build application name is invalid.'
    }

    $commands = @(Get-Command -Name $Name `
        -CommandType Application -ErrorAction Stop)
    if ($commands.Count -lt 1) {
        throw 'A required build application is unavailable.'
    }

    $source = [string]$commands[0].Source
    if (-not (Test-ArtifactSigningFullyQualifiedPath -Path $source)) {
        throw 'A required build application path is invalid.'
    }

    return $source
}

function Test-ArtifactSigningLowerSha256 {
    param([Parameter(Mandatory)][string] $Value)

    return $Value -cmatch '^[0-9a-f]{64}$'
}

function Test-ArtifactSigningUpperThumbprint {
    param([Parameter(Mandatory)][string] $Value)

    return $Value -cmatch '^[0-9A-F]{40}$'
}

function Test-ArtifactSigningAsciiBytes {
    param([Parameter(Mandatory)][byte[]] $Bytes)

    foreach ($value in $Bytes) {
        if ($value -gt 127) {
            return $false
        }
    }
    return $true
}

function Assert-ArtifactSigningDirectPath {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][bool] $Directory
    )

    if (-not (Test-ArtifactSigningFullyQualifiedPath -Path $Path)) {
        throw 'An installer path is not fully qualified.'
    }

    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -ne $Directory -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'An installer path is not a direct file or directory.'
    }
    if (-not $Directory -and
        $null -ne $item.PSObject.Properties['LinkType'] -and
        $item.LinkType -eq 'HardLink') {
        throw 'An installer file has more than one hard link.'
    }

    $current = if ($Directory) { $item } else { $item.Directory }
    while ($null -ne $current) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'An installer path has a reparse-point ancestor.'
        }

        $current = $current.Parent
    }
}

function Get-ArtifactSigningRelativePath {
    param(
        [Parameter(Mandatory)][string] $Root,
        [Parameter(Mandatory)][string] $Path
    )

    $canonicalRoot = [IO.Path]::GetFullPath($Root).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
    $canonicalPath = [IO.Path]::GetFullPath($Path)
    $prefix = "$canonicalRoot$([IO.Path]::DirectorySeparatorChar)"
    if (-not $canonicalPath.StartsWith(
            $prefix,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'An installer file escapes its package root.'
    }

    return $canonicalPath.Substring($prefix.Length).Replace(
        [IO.Path]::DirectorySeparatorChar,
        '/')
}

function Read-ArtifactSigningDeployment {
    param([Parameter(Mandatory)][string] $Path)

    return Read-ArtifactSigningDeploymentWithReviewedRollbackCompatibility `
        -Path $Path `
        -AllowReviewedRollbackCompatibility $false
}

function Read-ArtifactSigningReviewedRollbackDeployment {
    param([Parameter(Mandatory)][string] $Path)

    return Read-ArtifactSigningDeploymentWithReviewedRollbackCompatibility `
        -Path $Path `
        -AllowReviewedRollbackCompatibility $true
}

function Read-ArtifactSigningDeploymentWithReviewedRollbackCompatibility {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][bool] $AllowReviewedRollbackCompatibility
    )

    $acceptedInstallerVersions = @($script:ArtifactSigningInstallerVersion)
    if ($AllowReviewedRollbackCompatibility) {
        $acceptedInstallerVersions += @(
            $script:ArtifactSigningRollbackLegacyInstallerVersions)
    }
    if ($acceptedInstallerVersions.Count -lt 1 -or
        @($acceptedInstallerVersions | Sort-Object -Unique).Count -ne
            $acceptedInstallerVersions.Count -or
        @($acceptedInstallerVersions | Where-Object {
                $_ -cnotmatch
                    '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
            }).Count -ne 0) {
        throw 'The reviewed installer version policy is invalid.'
    }

    Assert-ArtifactSigningDirectPath -Path $Path -Directory $false
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 1 -or $bytes.Length -gt 16384 -or
        -not (Test-ArtifactSigningAsciiBytes -Bytes $bytes)) {
        throw 'The installer deployment file is invalid.'
    }

    $text = [Text.Encoding]::ASCII.GetString($bytes)
    if ($text.Contains("`r") -or -not $text.EndsWith("`n")) {
        throw 'The installer deployment file is not canonical LF text.'
    }

    $values = @{}
    foreach ($line in $text.Split(
            [char[]]@("`n"),
            [StringSplitOptions]::RemoveEmptyEntries)) {
        if ($line -cnotmatch '^([A-Za-z][A-Za-z0-9]*)=([ -~]*)$') {
            throw 'The installer deployment file has an invalid line.'
        }

        $key = $Matches[1]
        $value = $Matches[2]
        if ($script:ExpectedDeploymentKeys -cnotcontains $key -or
            $values.ContainsKey($key)) {
            throw 'The installer deployment file has an unknown or duplicate key.'
        }

        $values.Add($key, $value)
    }

    $expectedKeys = switch ($values.Format) {
        'ArtifactSigningInstallerDeploymentV2' {
            @($script:ExpectedDeploymentV2Keys)
            break
        }
        'ArtifactSigningInstallerDeploymentV3' {
            @($script:ExpectedDeploymentV3Keys)
            break
        }
        default {
            throw 'The installer deployment identity is invalid.'
        }
    }
    $missingKeys = @($expectedKeys |
        Where-Object { -not $values.ContainsKey($_) })
    if ($values.Count -ne $expectedKeys.Count -or
        $missingKeys.Count -ne 0) {
        throw 'The installer deployment file is incomplete.'
    }

    if ($values.ReleaseVersion -cnotmatch
            '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' -or
        $values.SourceCommit -cnotmatch '^[0-9a-f]{40}$' -or
        $acceptedInstallerVersions -cnotcontains
            $values.InstallerVersion -or
        $values.GatewayVersion -cnotmatch
            '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' -or
        $values.WorkerVersion -cnotmatch
            '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' -or
        $values.CliVersion -cnotmatch
            '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' -or
        -not (Test-ArtifactSigningLowerSha256 -Value $values.ProfileSetSha256)) {
        throw 'The installer deployment identity is invalid.'
    }

    $signingProvider = if (
        $values.Format -ceq 'ArtifactSigningInstallerDeploymentV2') {
        'LocalMachineCertificate'
    }
    else {
        [string]$values.SigningProvider
    }
    if (($values.Format -ceq 'ArtifactSigningInstallerDeploymentV2' -and
            $signingProvider -cne 'LocalMachineCertificate') -or
        ($values.Format -ceq 'ArtifactSigningInstallerDeploymentV3' -and
            $signingProvider -cne 'MicrosoftArtifactSigning')) {
        throw 'The installer signing-provider policy is invalid.'
    }

    $listenAddress = $null
    if (-not [Net.IPAddress]::TryParse(
            $values.GatewayListenAddress,
            [ref]$listenAddress) -or
        $listenAddress.Equals([Net.IPAddress]::Any) -or
        $listenAddress.Equals([Net.IPAddress]::IPv6Any)) {
        throw 'The installer network policy is invalid.'
    }

    $listenPort = 0
    if (-not [int]::TryParse(
            $values.GatewayListenPort,
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$listenPort) -or
        $listenPort -lt 1 -or $listenPort -gt 65535) {
        throw 'The installer port policy is invalid.'
    }

    $relayAddress = $null
    $relayPort = 0
    if ($signingProvider -ceq 'LocalMachineCertificate') {
        if (-not [Net.IPAddress]::TryParse(
                $values.TimestampRelayAddress,
                [ref]$relayAddress) -or
            $relayAddress.Equals([Net.IPAddress]::Any) -or
            $relayAddress.Equals([Net.IPAddress]::IPv6Any) -or
            -not [int]::TryParse(
                $values.TimestampRelayPort,
                [Globalization.NumberStyles]::None,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$relayPort) -or
            $relayPort -lt 1 -or $relayPort -gt 65535) {
            throw 'The installer network policy is invalid.'
        }
    }
    elseif ($values.TimestampRelayAddress.Length -ne 0 -or
        $values.TimestampRelayPort.Length -ne 0) {
        throw 'The installer network policy is invalid.'
    }

    $ingress = @(ConvertTo-ArtifactSigningIpList `
        -Value $values.GatewayIngressRemoteAddresses `
        -Minimum 1 -Maximum 32)
    $certificateStatus = @(ConvertTo-ArtifactSigningIpList `
        -Value $values.CertificateStatusRemoteAddresses `
        -Minimum 0 -Maximum 32)
    $timeServers = @(ConvertTo-ArtifactSigningIpList `
        -Value $values.TimeServerAddresses `
        -Minimum 1 -Maximum 8)
    $dnsServers = if (
        $signingProvider -ceq 'MicrosoftArtifactSigning') {
        @(ConvertTo-ArtifactSigningIpList `
            -Value $values.DnsServerAddresses `
            -Minimum 1 -Maximum 8)
    }
    else {
        @()
    }

    $certificateIdentities = @(
        $values.GatewayTlsCertificateThumbprint
        $values.ReceiptCertificateThumbprint
    )
    if ($signingProvider -ceq 'LocalMachineCertificate') {
        $certificateIdentities += @(
            $values.AuthenticodeCertificateThumbprint)
    }
    $certificateIdentityCount = $certificateIdentities |
        Sort-Object -Unique | Measure-Object |
        Select-Object -ExpandProperty Count
    $expectedCertificateIdentityCount = if (
        $signingProvider -ceq 'LocalMachineCertificate') {
        3
    }
    else {
        2
    }
    if (-not (Test-ArtifactSigningUpperThumbprint `
            -Value $values.GatewayTlsCertificateThumbprint) -or
        -not (Test-ArtifactSigningUpperThumbprint `
            -Value $values.ReceiptCertificateThumbprint) -or
        ($signingProvider -ceq 'LocalMachineCertificate' -and
            -not (Test-ArtifactSigningUpperThumbprint `
                -Value $values.AuthenticodeCertificateThumbprint)) -or
        ($signingProvider -ceq 'MicrosoftArtifactSigning' -and
            $values.AuthenticodeCertificateThumbprint.Length -ne 0) -or
        $certificateIdentityCount -ne $expectedCertificateIdentityCount) {
        throw 'The installer certificate policy is invalid.'
    }

    if (-not (Test-ArtifactSigningWindowsDeploymentPath `
            -Path $values.SignToolPath) -or
        -not $values.SignToolPath.EndsWith(
            '\signtool.exe',
            [StringComparison]::Ordinal) -or
        -not (Test-ArtifactSigningLowerSha256 `
            -Value $values.SignToolSha256)) {
        throw 'The installer SignTool policy is invalid.'
    }

    $signToolVersion = $null
    if (-not [Version]::TryParse(
            $values.SignToolFileVersion,
            [ref]$signToolVersion) -or
        $signToolVersion.ToString() -cne $values.SignToolFileVersion -or
        $signToolVersion.Revision -lt 0) {
        throw 'The installer SignTool version is invalid.'
    }

    $trustedPublisherRoots = @()
    $microsoftArtifactSigningRuntimeMajor = 0
    $microsoftArtifactSigningSignToolTimeoutSeconds = 0
    if ($signingProvider -ceq 'MicrosoftArtifactSigning') {
        $supportedRegions = @(
            'BrazilSouth',
            'CentralUS',
            'EastUS',
            'JapanEast',
            'KoreaCentral',
            'NorthCentralUS',
            'NorthEurope',
            'PolandCentral',
            'SouthCentralUS',
            'SwitzerlandNorth',
            'WestCentralUS',
            'WestEurope',
            'WestUS',
            'WestUS2',
            'WestUS3'
        )
        if ($values.ManagedEgressPolicy -cne
                'ProcessScopedTlsValidatedInternet' -or
            $supportedRegions -cnotcontains
                $values.MicrosoftArtifactSigningRegion -or
            $values.MicrosoftArtifactSigningAccountName -cnotmatch
                '^[a-z](?:[a-z0-9]|-(?!-)){1,22}[a-z0-9]$' -or
            $values.MicrosoftArtifactSigningAccountName.StartsWith(
                'one',
                [StringComparison]::Ordinal) -or
            $values.MicrosoftArtifactSigningCertificateProfileName -cnotmatch
                '^[A-Za-z](?:[A-Za-z0-9]|-(?!-)){3,98}[A-Za-z0-9]$' -or
            -not (Test-ArtifactSigningLowerSha256 `
                -Value $values.MicrosoftArtifactSigningDlibSha256) -or
            -not (Test-ArtifactSigningLowerSha256 `
                -Value $values.MicrosoftArtifactSigningClientToolsInventorySha256) -or
            -not (Test-ArtifactSigningLowerSha256 `
                -Value $values.MicrosoftArtifactSigningExpectedPublisherSubjectNameSha256) -or
            $values.MicrosoftArtifactSigningRequiredPublisherEnhancedKeyUsageOid `
                -cnotmatch '^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))+$' -or
            $values.MicrosoftArtifactSigningAuthenticodeRevocationPolicy `
                -cnotin @('Online', 'DisposableTestNoCheck')) {
            throw 'The installer Microsoft Artifact Signing policy is invalid.'
        }

        $dlibVersion = $null
        if (-not [Version]::TryParse(
                $values.MicrosoftArtifactSigningDlibFileVersion,
                [ref]$dlibVersion) -or
            $dlibVersion.Revision -lt 0 -or
            $dlibVersion.ToString() -cne
                $values.MicrosoftArtifactSigningDlibFileVersion -or
            -not [int]::TryParse(
                $values.MicrosoftArtifactSigningRuntimeMajor,
                [Globalization.NumberStyles]::None,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$microsoftArtifactSigningRuntimeMajor) -or
            $microsoftArtifactSigningRuntimeMajor -lt 8 -or
            $microsoftArtifactSigningRuntimeMajor -gt 99 -or
            -not [int]::TryParse(
                $values.MicrosoftArtifactSigningSignToolTimeoutSeconds,
                [Globalization.NumberStyles]::None,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$microsoftArtifactSigningSignToolTimeoutSeconds) -or
            $microsoftArtifactSigningSignToolTimeoutSeconds -lt 1 -or
            $microsoftArtifactSigningSignToolTimeoutSeconds -gt 120) {
            throw 'The installer Microsoft Artifact Signing policy is invalid.'
        }

        $trustedPublisherRoots = @(
            ConvertTo-ArtifactSigningThumbprintList `
                -Value $values.MicrosoftArtifactSigningTrustedPublisherRootThumbprints `
                -Minimum 1 -Maximum 8)
    }

    [pscustomobject]@{
        Values = $values
        SigningProvider = $signingProvider
        IsMicrosoftArtifactSigning =
            $signingProvider -ceq 'MicrosoftArtifactSigning'
        GatewayListenAddress = $listenAddress.ToString()
        GatewayListenPort = $listenPort
        GatewayIngressRemoteAddresses = @($ingress)
        TimestampRelayAddress = if ($null -eq $relayAddress) {
            $null
        }
        else {
            $relayAddress.ToString()
        }
        TimestampRelayPort = $relayPort
        CertificateStatusRemoteAddresses = @($certificateStatus)
        TimeServerAddresses = @($timeServers)
        DnsServerAddresses = @($dnsServers)
        MicrosoftArtifactSigningTrustedPublisherRootThumbprints =
            @($trustedPublisherRoots)
        MicrosoftArtifactSigningRuntimeMajor =
            $microsoftArtifactSigningRuntimeMajor
        MicrosoftArtifactSigningSignToolTimeoutSeconds =
            $microsoftArtifactSigningSignToolTimeoutSeconds
    }
}

function ConvertTo-ArtifactSigningIpList {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string] $Value,
        [Parameter(Mandatory)][int] $Minimum,
        [Parameter(Mandatory)][int] $Maximum
    )

    $parts = @()
    if ($Value.Length -ne 0) {
        $parts = @($Value.Split(','))
    }
    if ($parts.Count -lt $Minimum -or $parts.Count -gt $Maximum -or
        @($parts | Sort-Object -Unique).Count -ne $parts.Count) {
        throw 'An installer address allowlist is invalid.'
    }

    $result = @()
    foreach ($part in $parts) {
        $address = $null
        if (-not [Net.IPAddress]::TryParse($part, [ref]$address) -or
            $address.Equals([Net.IPAddress]::Any) -or
            $address.Equals([Net.IPAddress]::IPv6Any) -or
            $address.IsIPv4MappedToIPv6) {
            throw 'An installer address allowlist is invalid.'
        }

        $result += $address.ToString()
    }

    return @($result)
}

function ConvertTo-ArtifactSigningThumbprintList {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string] $Value,
        [Parameter(Mandatory)][int] $Minimum,
        [Parameter(Mandatory)][int] $Maximum
    )

    $parts = @()
    if ($Value.Length -ne 0) {
        $parts = @($Value.Split(','))
    }
    if ($parts.Count -lt $Minimum -or $parts.Count -gt $Maximum -or
        @($parts | Sort-Object -Unique).Count -ne $parts.Count -or
        @($parts | Where-Object {
                -not (Test-ArtifactSigningUpperThumbprint -Value $_)
            }).Count -ne 0) {
        throw 'An installer certificate thumbprint allowlist is invalid.'
    }

    return @($parts)
}

function Test-ArtifactSigningProfileSetLock {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][string] $ExpectedProfileSetSha256
    )

    if (-not (Test-ArtifactSigningLowerSha256 -Value $ExpectedProfileSetSha256)) {
        throw 'The expected profile-set identity is invalid.'
    }

    Assert-ArtifactSigningDirectPath -Path $Path -Directory $false
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 1 -or $bytes.Length -gt 65536 -or
        -not (Test-ArtifactSigningAsciiBytes -Bytes $bytes)) {
        throw 'The profile-set lock is invalid.'
    }

    $text = [Text.Encoding]::ASCII.GetString($bytes)
    if ($text.Contains("`r") -or -not $text.EndsWith("`n")) {
        throw 'The profile-set lock is not canonical LF text.'
    }

    [string[]] $lines = $text.Split(
        [char[]]@("`n"),
        [StringSplitOptions]::None)
    if ($lines.Count -lt 5 -or $lines[$lines.Count - 1] -cne '' -or
        $lines[0] -cne 'Format=ArtifactSigningProfileSetLockV1' -or
        $lines[1] -cne 'AbiVersion=1' -or
        $lines[2] -cne "PackageSetSha256=$ExpectedProfileSetSha256") {
        throw 'The profile-set lock identity is invalid.'
    }

    $packageIds = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $profileIdentities = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $packageCount = 0
    $profileCount = 0
    for ($index = 3; $index -lt ($lines.Count - 1); $index++) {
        $line = $lines[$index]
        if ($line -cmatch (
                '^Package=([A-Za-z0-9][A-Za-z0-9._-]{0,63})\|' +
                '((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)' +
                '(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*' +
                '(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?' +
                '(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)\|' +
                '([0-9a-f]{64})\|([0-9a-f]{64})\|([0-9a-f]{64})$')) {
            if (-not $packageIds.Add($Matches[1])) {
                throw 'The profile-set lock has a duplicate package.'
            }

            $packageCount++
            continue
        }

        if ($line -cmatch (
                '^Profile=([A-Za-z0-9][A-Za-z0-9._-]{0,63})\|' +
                '([A-Za-z0-9][A-Za-z0-9._-]{0,63})\|' +
                '([1-9][0-9]{0,9})\|([0-9a-f]{64})$')) {
            if (-not $packageIds.Contains($Matches[1]) -or
                -not $profileIdentities.Add(
                    "$($Matches[1])|$($Matches[2])|$($Matches[3])")) {
                throw 'The profile-set lock has an invalid profile entry.'
            }

            $profileCount++
            continue
        }

        throw 'The profile-set lock has an invalid entry.'
    }

    if ($packageCount -lt 1 -or $packageCount -gt 64 -or
        $profileCount -lt 1 -or $profileCount -gt 64) {
        throw 'The profile-set lock is incomplete.'
    }
}

function Read-ArtifactSigningReleaseInventory {
    param(
        [Parameter(Mandatory)][string] $PackageRoot,
        [Parameter(Mandatory)][string] $ExpectedInventorySha256
    )

    if (-not (Test-ArtifactSigningLowerSha256 `
            -Value $ExpectedInventorySha256)) {
        throw 'The independently supplied release hash is invalid.'
    }

    Assert-ArtifactSigningDirectPath -Path $PackageRoot -Directory $true
    $inventoryPath = Join-Path $PackageRoot $script:ReleaseInventoryName
    Assert-ArtifactSigningDirectPath -Path $inventoryPath -Directory $false
    $inventoryDigest = (
        Get-FileHash -LiteralPath $inventoryPath -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if ($inventoryDigest -cne $ExpectedInventorySha256) {
        throw 'The release inventory hash does not match.'
    }

    $bytes = [IO.File]::ReadAllBytes($inventoryPath)
    if ($bytes.Length -lt 1 -or $bytes.Length -gt 1048576 -or
        -not (Test-ArtifactSigningAsciiBytes -Bytes $bytes)) {
        throw 'The release inventory is invalid.'
    }

    $text = [Text.Encoding]::ASCII.GetString($bytes)
    if ($text.Contains("`r") -or -not $text.EndsWith("`n")) {
        throw 'The release inventory is not canonical LF text.'
    }

    $entries = @()
    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    foreach ($line in $text.Split(
            [char[]]@("`n"),
            [StringSplitOptions]::RemoveEmptyEntries)) {
        if ($line -cnotmatch (
            '^([0-9a-f]{64}) ([1-9][0-9]{0,9}) (' +
            '(?:Gateway/[A-Za-z0-9._-]+|' +
            'Worker/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*)|' +
            'config/(?:gateway|worker)\.template\.json|' +
            'installer/(?:[A-Za-z0-9._-]+\.ps1|artifact-signctl\.exe)|' +
            'profiles/profile-set\.lock|' +
            'deployment\.txt)$')) {
            throw 'The release inventory has an invalid entry.'
        }

        $entrySha256 = $Matches[1]
        $entryLength = [long]$Matches[2]
        $relativePath = $Matches[3]
        if ($relativePath.Contains('//') -or
            $relativePath.Split('/') -contains '..' -or
            -not $seen.Add($relativePath) -or
            $relativePath -cmatch
                '\.(?:pfx|p12|pem|key|pvk|snk|jks|kdbx)$' -or
            $relativePath -cmatch
                '^(?:Gateway|Worker)/(?:gateway|worker)\.json$' -or
            ($relativePath -cmatch '^installer/' -and
                $relativePath -cnotmatch
                    '^installer/(?:[A-Za-z0-9._-]+\.ps1|artifact-signctl\.exe)$') -or
            ($relativePath -cmatch '^config/' -and
                $relativePath -cnotmatch
                    '^config/(?:gateway|worker)\.template\.json$')) {
            throw 'The release inventory has an ambiguous entry.'
        }

        $fullPath = Join-Path $PackageRoot (
            $relativePath.Replace('/', [IO.Path]::DirectorySeparatorChar))
        Assert-ArtifactSigningDirectPath -Path $fullPath -Directory $false
        $file = Get-Item -LiteralPath $fullPath -Force
        if ($file.Length -ne $entryLength -or
            (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).
                Hash.ToLowerInvariant() -cne $entrySha256) {
            throw 'A release file does not match its inventory.'
        }
        $prefixLength = [Math]::Min(4096, [int]$file.Length)
        if ($prefixLength -gt 0) {
            $stream = [IO.File]::Open(
                $fullPath,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Read,
                [IO.FileShare]::Read)
            try {
                $prefixBytes = [byte[]]::new($prefixLength)
                $read = $stream.Read(
                    $prefixBytes,
                    0,
                    $prefixBytes.Length)
                $prefixText = [Text.Encoding]::ASCII.GetString(
                    $prefixBytes,
                    0,
                    $read)
                if ($prefixText.Contains(
                        '-----BEGIN PRIVATE KEY') -or
                    $prefixText.Contains(
                        '-----BEGIN ENCRYPTED PRIVATE KEY') -or
                    $prefixText.Contains(
                        '-----BEGIN RSA PRIVATE KEY')) {
                    throw 'A release file contains prohibited private-key material.'
                }
            }
            finally {
                $stream.Dispose()
            }
        }

        $entries += [pscustomobject]@{
            Sha256 = $entrySha256
            Length = $entryLength
            RelativePath = $relativePath
            FullPath = $fullPath
        }
    }

    if ($entries.Count -lt 5 -or
        -not $seen.Contains($script:DeploymentName) -or
        -not $seen.Contains('config/gateway.template.json') -or
        -not $seen.Contains('config/worker.template.json') -or
        -not $seen.Contains('profiles/profile-set.lock') -or
        -not $seen.Contains(
            'Gateway/ArtifactSigning.Gateway.exe') -or
        -not $seen.Contains(
            'Worker/ArtifactSigning.Worker.exe') -or
        -not $seen.Contains(
            'installer/ArtifactSigning.Installer.ps1') -or
        -not $seen.Contains(
            'installer/install-artifact-signing-service.ps1') -or
        -not $seen.Contains(
            'installer/verify-artifact-signing-service.ps1') -or
        -not $seen.Contains(
            'installer/uninstall-artifact-signing-service.ps1') -or
        -not $seen.Contains(
            'installer/rollback-artifact-signing-service.ps1') -or
        -not $seen.Contains(
            'installer/artifact-signctl.exe') -or
        -not ($entries.RelativePath |
            Where-Object { $_ -cmatch '^Gateway/.+' }) -or
        -not ($entries.RelativePath |
            Where-Object { $_ -cmatch '^Worker/.+' })) {
        throw 'The release inventory is incomplete.'
    }

    $actualFiles = @(
        Get-ChildItem -LiteralPath $PackageRoot -File -Recurse -Force |
            ForEach-Object {
                Assert-ArtifactSigningDirectPath `
                    -Path $_.FullName -Directory $false
                Get-ArtifactSigningRelativePath `
                    -Root $PackageRoot -Path $_.FullName
            } |
            Where-Object { $_ -cne $script:ReleaseInventoryName } |
            Sort-Object
    )
    $expectedFiles = @($entries.RelativePath | Sort-Object)
    if ([string]::Join("`n", $actualFiles) -cne
        [string]::Join("`n", $expectedFiles)) {
        throw 'The release package contains an unexpected or missing file.'
    }

    return @($entries)
}

function Get-ArtifactSigningMicrosoftClientToolsInventorySha256 {
    param([Parameter(Mandatory)][string] $Directory)

    Assert-ArtifactSigningDirectPath -Path $Directory -Directory $true
    $children = @(Get-ChildItem -LiteralPath $Directory -Force)
    if ($children.Count -lt 1 -or $children.Count -gt 128 -or
        @($children | Where-Object {
                $_.PSIsContainer -or
                $_.Name -cnotmatch '^[A-Za-z0-9._-]{1,128}$' -or
                $_.Length -lt 1 -or $_.Length -gt 104857600 -or
                ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                ($null -ne $_.PSObject.Properties['LinkType'] -and
                    $null -ne $_.LinkType)
            }).Count -ne 0) {
        throw 'ArtifactSigningMicrosoftClientToolsFailed:Inventory'
    }

    [string[]] $names = @($children.Name)
    [Array]::Sort($names, [StringComparer]::Ordinal)
    $stream = [IO.MemoryStream]::new()
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        foreach ($name in $names) {
            $item = Get-Item -LiteralPath (
                Join-Path $Directory $name) -Force
            Assert-ArtifactSigningDirectPath `
                -Path $item.FullName -Directory $false
            $digest = (Get-FileHash -LiteralPath $item.FullName `
                -Algorithm SHA256).Hash.ToLowerInvariant()
            $record = '{0}{1}{2}{1}{3}{4}' -f @(
                $item.Name,
                [char]0,
                $item.Length.ToString(
                    [Globalization.CultureInfo]::InvariantCulture),
                $digest,
                [char]10)
            $recordBytes = [Text.Encoding]::UTF8.GetBytes($record)
            $stream.Write($recordBytes, 0, $recordBytes.Length)
        }

        return ([BitConverter]::ToString(
            $sha256.ComputeHash($stream.ToArray()))).Replace(
                '-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
        $stream.Dispose()
    }
}

function Test-ArtifactSigningMicrosoftArtifactSigningClientTools {
    param(
        [Parameter(Mandatory)][string] $Directory,
        [Parameter(Mandatory)] $Deployment,
        [Parameter()][bool] $RequireInstalledRuntime = $true
    )

    if (-not $Deployment.IsMicrosoftArtifactSigning) {
        return
    }

    try {
        $inventorySha256 =
            Get-ArtifactSigningMicrosoftClientToolsInventorySha256 `
                -Directory $Directory
        $dlib = Join-Path $Directory 'Azure.CodeSigning.Dlib.dll'
        Assert-ArtifactSigningDirectPath -Path $dlib -Directory $false
        if ((Get-FileHash -LiteralPath $dlib -Algorithm SHA256).
                Hash.ToLowerInvariant() -cne
                    $Deployment.Values.MicrosoftArtifactSigningDlibSha256 -or
            [Diagnostics.FileVersionInfo]::GetVersionInfo($dlib).FileVersion `
                -cne $Deployment.Values.MicrosoftArtifactSigningDlibFileVersion -or
            $inventorySha256 -cne
                $Deployment.Values.MicrosoftArtifactSigningClientToolsInventorySha256) {
            throw 'PinnedContent'
        }

        if ($RequireInstalledRuntime) {
            $programFiles = [Environment]::GetFolderPath(
                [Environment+SpecialFolder]::ProgramFiles)
            $runtimeRoot = Join-Path $programFiles `
                'dotnet\shared\Microsoft.NETCore.App'
            Assert-ArtifactSigningDirectPath `
                -Path $runtimeRoot -Directory $true
            $runtimePattern = '^{0}\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$' -f
                $Deployment.MicrosoftArtifactSigningRuntimeMajor
            $runtimes = @(Get-ChildItem -LiteralPath $runtimeRoot `
                -Directory -Force | Where-Object {
                    $_.Name -cmatch $runtimePattern -and
                    ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0
                })
            if ($runtimes.Count -lt 1) {
                throw 'Runtime'
            }
        }
    }
    catch {
        if ([string]$_.Exception.Message -ceq 'Runtime') {
            throw 'ArtifactSigningMicrosoftClientToolsFailed:Runtime'
        }
        throw 'ArtifactSigningMicrosoftClientToolsFailed:Validation'
    }
}

function Get-ArtifactSigningServiceSid {
    param([Parameter(Mandatory)][string] $ServiceName)

    $account = [Security.Principal.NTAccount]::new(
        'NT SERVICE',
        $ServiceName)
    try {
        return $account.Translate(
            [Security.Principal.SecurityIdentifier])
    }
    catch [Security.Principal.IdentityNotMappedException] {
        throw 'A required virtual service identity is unavailable.'
    }
}

function New-ArtifactSigningFileSystemRule {
    param(
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier] $Sid,
        [Parameter(Mandatory)]
        [Security.AccessControl.FileSystemRights] $Rights,
        [Parameter(Mandatory)][bool] $Directory
    )

    if ($Directory) {
        return [Security.AccessControl.FileSystemAccessRule]::new(
            $Sid,
            $Rights,
            [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)
    }

    return [Security.AccessControl.FileSystemAccessRule]::new(
        $Sid,
        $Rights,
        [Security.AccessControl.AccessControlType]::Allow)
}

function Set-ArtifactSigningExactAcl {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier[]] $FullControl,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [Security.Principal.SecurityIdentifier[]] $ReadAndExecute,
        [Parameter(Mandatory)][bool] $Directory
    )

    Assert-ArtifactSigningDirectPath -Path $Path -Directory $Directory
    $security = if ($Directory) {
        [Security.AccessControl.DirectorySecurity]::new()
    }
    else {
        [Security.AccessControl.FileSecurity]::new()
    }
    $security.SetOwner([Security.Principal.SecurityIdentifier]::new(
        [Security.Principal.WellKnownSidType]::LocalSystemSid,
        $null))
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in $FullControl) {
        $security.AddAccessRule((New-ArtifactSigningFileSystemRule `
            -Sid $sid `
            -Rights ([Security.AccessControl.FileSystemRights]::FullControl) `
            -Directory $Directory))
    }
    foreach ($sid in $ReadAndExecute) {
        $security.AddAccessRule((New-ArtifactSigningFileSystemRule `
            -Sid $sid `
            -Rights ([Security.AccessControl.FileSystemRights]::ReadAndExecute) `
            -Directory $Directory))
    }

    if ($Directory) {
        Set-Acl -LiteralPath $Path -AclObject $security
    }
    else {
        Set-Acl -LiteralPath $Path -AclObject $security
    }
}

function Test-ArtifactSigningExactAcl {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier[]] $FullControl,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [Security.Principal.SecurityIdentifier[]] $ReadAndExecute,
        [Parameter(Mandatory)][bool] $Directory
    )

    try {
        Assert-ArtifactSigningDirectPath -Path $Path -Directory $Directory
    }
    catch {
        throw 'ArtifactSigningExactAclFailed:DirectPath'
    }
    try {
        $security = if ($Directory) {
            Get-Acl -LiteralPath $Path -Audit:$false
        }
        else {
            Get-Acl -LiteralPath $Path -Audit:$false
        }
    }
    catch {
        throw 'ArtifactSigningExactAclFailed:SecurityDescriptor'
    }

    try {
        $systemSid = [Security.Principal.SecurityIdentifier]::new(
            [Security.Principal.WellKnownSidType]::LocalSystemSid,
            $null)
        $owner = $security.GetOwner(
            [Security.Principal.SecurityIdentifier])
        $rulesProtected = $security.AreAccessRulesProtected
    }
    catch {
        throw 'ArtifactSigningExactAclFailed:OwnerOrProtection'
    }
    if (-not $rulesProtected -or $owner.Value -cne $systemSid.Value) {
        throw 'ArtifactSigningExactAclFailed:OwnerOrProtection'
    }

    try {
        $rules = @($security.GetAccessRules(
            $true,
            $true,
            [Security.Principal.SecurityIdentifier]))
    }
    catch {
        throw 'ArtifactSigningExactAclFailed:Rules'
    }
    try {
        $normalizedRules = @(
            foreach ($rule in $rules) {
                [pscustomobject]@{
                    Identity = [string]$rule.IdentityReference.Value
                    Rights = $rule.FileSystemRights
                    IsInherited = [bool]$rule.IsInherited
                    AccessType = $rule.AccessControlType
                    InheritanceFlags = if ($Directory) {
                        $rule.InheritanceFlags
                    }
                    else {
                        $null
                    }
                    PropagationFlags = if ($Directory) {
                        $rule.PropagationFlags
                    }
                    else {
                        $null
                    }
                }
            }
        )
    }
    catch {
        throw 'ArtifactSigningExactAclFailed:Rules'
    }

    if ($normalizedRules.Count -ne
        $FullControl.Count + $ReadAndExecute.Count) {
        throw 'ArtifactSigningExactAclFailed:Rules'
    }
    foreach ($rule in $normalizedRules) {
        if ($rule.IsInherited -or
            $rule.AccessType -ne
                [Security.AccessControl.AccessControlType]::Allow) {
            throw 'ArtifactSigningExactAclFailed:Rules'
        }
    }

    foreach ($sid in $FullControl) {
        $matchingCount = 0
        foreach ($rule in $normalizedRules) {
            if ($rule.Identity -ceq $sid.Value -and
                $rule.Rights -eq
                    [Security.AccessControl.FileSystemRights]::FullControl -and
                (-not $Directory -or
                    ($rule.InheritanceFlags -eq
                        [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' -and
                     $rule.PropagationFlags -eq
                        [Security.AccessControl.PropagationFlags]::None))) {
                $matchingCount++
            }
        }
        if ($matchingCount -ne 1) {
            throw 'ArtifactSigningExactAclFailed:Rules'
        }
    }
    # FileSystemAccessRule automatically adds Synchronize to an allow ACE.
    # Compare the persisted canonical mask rather than the requested shorthand.
    $persistedReadAndExecute =
        [Security.AccessControl.FileSystemRights](
            [int][Security.AccessControl.FileSystemRights]::ReadAndExecute `
            -bor
            [int][Security.AccessControl.FileSystemRights]::Synchronize)
    foreach ($sid in $ReadAndExecute) {
        $matchingCount = 0
        foreach ($rule in $normalizedRules) {
            if ($rule.Identity -ceq $sid.Value -and
                $rule.Rights -eq $persistedReadAndExecute -and
                (-not $Directory -or
                    ($rule.InheritanceFlags -eq
                        [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' -and
                     $rule.PropagationFlags -eq
                        [Security.AccessControl.PropagationFlags]::None))) {
                $matchingCount++
            }
        }
        if ($matchingCount -ne 1) {
            throw 'ArtifactSigningExactAclFailed:Rules'
        }
    }
}

function Test-ArtifactSigningUpdateExecutionTrustAcl {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][bool] $Directory
    )

    Assert-ArtifactSigningDirectPath -Path $Path -Directory $Directory
    $security = Get-Acl -LiteralPath $Path -Audit:$false
    $builtIn = Get-ArtifactSigningBuiltInSids
    $owner = $security.GetOwner(
        [Security.Principal.SecurityIdentifier])
    if (-not $security.AreAccessRulesProtected -or
        $owner.Value -cne $builtIn.System.Value) {
        throw 'The update execution path owner or protection is invalid.'
    }

    $unsafeRights = [Security.AccessControl.FileSystemRights](
        [int][Security.AccessControl.FileSystemRights]::WriteData -bor
        [int][Security.AccessControl.FileSystemRights]::AppendData -bor
        [int][Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [int][Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [int][Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [int][Security.AccessControl.FileSystemRights]::Delete -bor
        [int][Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [int][Security.AccessControl.FileSystemRights]::TakeOwnership)
    $systemFullControl = 0
    $administratorsFullControl = 0
    $rules = @($security.GetAccessRules(
        $true,
        $true,
        [Security.Principal.SecurityIdentifier]))
    foreach ($rule in $rules) {
        $identity = [string]$rule.IdentityReference.Value
        $rights = $rule.FileSystemRights
        if ($rule.IsInherited -or
            $rule.AccessControlType -ne
                [Security.AccessControl.AccessControlType]::Allow) {
            throw 'The update execution path ACL is invalid.'
        }
        if ($identity -ceq $builtIn.System.Value) {
            if ($rights -ne
                [Security.AccessControl.FileSystemRights]::FullControl) {
                throw 'The update execution path ACL is invalid.'
            }
            $systemFullControl++
        }
        elseif ($identity -ceq $builtIn.Administrators.Value) {
            if ($rights -ne
                [Security.AccessControl.FileSystemRights]::FullControl) {
                throw 'The update execution path ACL is invalid.'
            }
            $administratorsFullControl++
        }
        elseif (([int]$rights -band [int]$unsafeRights) -ne 0) {
            throw 'The update execution path is writable by an unprivileged identity.'
        }
    }
    if ($systemFullControl -ne 1 -or
        $administratorsFullControl -ne 1) {
        throw 'The update execution path ACL is invalid.'
    }
}

function Test-ArtifactSigningInstalledVerifierExecutionTrust {
    param([Parameter(Mandatory)] $Paths)

    foreach ($definition in @(
            @($Paths.InstallRoot, $true, 'InstallRoot'),
            @($Paths.InstallerRoot, $true, 'InstallerRoot'),
            @((Join-Path $Paths.InstallerRoot `
                'verify-artifact-signing-service.ps1'), $false, 'Verifier'),
            @((Join-Path $Paths.InstallerRoot `
                'ArtifactSigning.Installer.ps1'), $false, 'Common'))) {
        try {
            Test-ArtifactSigningUpdateExecutionTrustAcl `
                -Path $definition[0] -Directory $definition[1]
        }
        catch {
            throw "ArtifactSigningUpdateExecutionTrustFailed:$($definition[2])"
        }
    }
}

function Get-ArtifactSigningBuiltInSids {
    [pscustomobject]@{
        System = [Security.Principal.SecurityIdentifier]::new(
            [Security.Principal.WellKnownSidType]::LocalSystemSid,
            $null)
        Administrators = [Security.Principal.SecurityIdentifier]::new(
            [Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,
            $null)
    }
}

function Get-ArtifactSigningServiceControlPath {
    $windowsRoot = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::Windows)
    if ([string]::IsNullOrWhiteSpace($windowsRoot) -or
        -not (Test-ArtifactSigningFullyQualifiedPath -Path $windowsRoot)) {
        throw 'The Windows system directory is unavailable.'
    }

    $system32 = [IO.Path]::GetFullPath(
        (Join-Path $windowsRoot 'System32'))
    Assert-ArtifactSigningDirectPath -Path $system32 -Directory $true
    $expected = [IO.Path]::GetFullPath(
        (Join-Path $system32 'sc.exe'))
    $item = Get-Item -LiteralPath $expected -Force
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not $item.FullName.Equals(
            $expected,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The Windows Service Control Manager tool is invalid.'
    }

    # Windows services protected system binaries from WinSxS through NTFS hard
    # links. Package files must remain single-linked, but that rule cannot be
    # applied to this fixed Windows Resource Protection path.
    return $expected
}

function Get-ArtifactSigningWindowsTimePath {
    $windowsRoot = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::Windows)
    if ([string]::IsNullOrWhiteSpace($windowsRoot) -or
        -not (Test-ArtifactSigningFullyQualifiedPath -Path $windowsRoot)) {
        throw 'The Windows system directory is unavailable.'
    }

    $system32 = [IO.Path]::GetFullPath(
        (Join-Path $windowsRoot 'System32'))
    Assert-ArtifactSigningDirectPath -Path $system32 -Directory $true
    $expected = [IO.Path]::GetFullPath(
        (Join-Path $system32 'w32tm.exe'))
    $item = Get-Item -LiteralPath $expected -Force
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not $item.FullName.Equals(
            $expected,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The Windows Time tool is invalid.'
    }

    # Windows Resource Protection may expose this fixed system binary through
    # hard links, so package-file single-link rules do not apply here.
    return $expected
}

function ConvertTo-ArtifactSigningWindowsCommandLineArgument {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Value
    )

    if ($Value.Contains([char]0) -or
        $Value.Contains("`r") -or $Value.Contains("`n")) {
        throw 'A native service-control argument is invalid.'
    }
    if ($Value.Length -eq 0) {
        return '""'
    }
    if ($Value -cnotmatch '[\s"]') {
        return $Value
    }

    $encoded = [Text.StringBuilder]::new()
    $null = $encoded.Append('"')
    $backslashCount = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]'\') {
            $backslashCount++
            continue
        }
        if ($character -eq [char]'"') {
            $null = $encoded.Append(
                ('\' * (($backslashCount * 2) + 1)))
        }
        elseif ($backslashCount -gt 0) {
            $null = $encoded.Append(('\' * $backslashCount))
        }
        $null = $encoded.Append($character)
        $backslashCount = 0
    }
    if ($backslashCount -gt 0) {
        $null = $encoded.Append(('\' * ($backslashCount * 2)))
    }
    $null = $encoded.Append('"')
    return $encoded.ToString()
}

function Invoke-ArtifactSigningSc {
    param([Parameter(Mandatory)][string[]] $Arguments)

    try {
        $sc = Get-ArtifactSigningServiceControlPath
    }
    catch {
        throw 'ArtifactSigningServiceControlFailed:ToolValidation'
    }

    $process = $null
    try {
        $encodedArguments = @(
            $Arguments | ForEach-Object {
                ConvertTo-ArtifactSigningWindowsCommandLineArgument `
                    -Value $_
            }
        )
        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $sc
        $startInfo.Arguments = [string]::Join(' ', $encodedArguments)
        if (($sc.Length + $startInfo.Arguments.Length + 3) -gt 32767) {
            throw 'The Service Control Manager command line is too long.'
        }
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true

        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            throw 'The Service Control Manager tool did not start.'
        }
        $process.BeginOutputReadLine()
        $process.BeginErrorReadLine()
        if (-not $process.WaitForExit(30000)) {
            $process.Kill()
            $process.WaitForExit()
            throw 'The Service Control Manager operation timed out.'
        }
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            throw 'The Service Control Manager operation failed.'
        }
    }
    catch {
        throw 'ArtifactSigningServiceControlFailed:NativeOperation'
    }
    finally {
        if ($null -ne $process) {
            $process.Dispose()
        }
    }
}

function Invoke-ArtifactSigningWindowsTime {
    param([Parameter(Mandatory)][string[]] $Arguments)

    try {
        $w32tm = Get-ArtifactSigningWindowsTimePath
    }
    catch {
        throw 'ArtifactSigningTimePolicyFailed:ToolValidation'
    }

    $process = $null
    try {
        $encodedArguments = @(
            $Arguments | ForEach-Object {
                ConvertTo-ArtifactSigningWindowsCommandLineArgument `
                    -Value $_
            }
        )
        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $w32tm
        $startInfo.Arguments = [string]::Join(' ', $encodedArguments)
        if (($w32tm.Length + $startInfo.Arguments.Length + 3) -gt 32767) {
            throw 'The Windows Time command line is too long.'
        }
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true

        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            throw 'The Windows Time tool did not start.'
        }
        $process.BeginOutputReadLine()
        $process.BeginErrorReadLine()
        if (-not $process.WaitForExit(30000)) {
            $process.Kill()
            $process.WaitForExit()
            throw 'The Windows Time operation timed out.'
        }
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            throw 'The Windows Time operation failed.'
        }
    }
    catch {
        if ([string]$_.Exception.Message -ceq
            'ArtifactSigningTimePolicyFailed:ToolValidation') {
            throw
        }
        throw 'ArtifactSigningTimePolicyFailed:NativeOperation'
    }
    finally {
        if ($null -ne $process) {
            $process.Dispose()
        }
    }
}

function Invoke-ArtifactSigningServiceDefinitionOperation {
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'WorkerCreate',
            'WorkerIdentity',
            'WorkerStartMode',
            'WorkerSidType',
            'WorkerRecoveryActions',
            'WorkerRecoveryFlag',
            'GatewayCreate',
            'GatewayIdentity',
            'GatewayStartMode',
            'GatewaySidType',
            'GatewayRecoveryActions',
            'GatewayRecoveryFlag')]
        [string] $Operation,
        [Parameter(Mandatory)]
        [string[]] $Arguments
    )

    try {
        Invoke-ArtifactSigningSc -Arguments $Arguments
    }
    catch {
        if ([string]$_.Exception.Message -ceq
            'ArtifactSigningServiceControlFailed:ToolValidation') {
            throw 'ArtifactSigningServiceDefinitionFailed:ToolValidation'
        }
        throw "ArtifactSigningServiceDefinitionFailed:$Operation"
    }
}

function Get-ArtifactSigningWorkerServiceDependencies {
    param([Parameter(Mandatory)] $Deployment)

    if ($Deployment.IsMicrosoftArtifactSigning) {
        return @('himds', 'W32Time')
    }
    return @('W32Time')
}

function Get-ArtifactSigningAzureArcPolicy {
    $programFiles = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::ProgramFiles)
    [pscustomobject]@{
        HybridApplicationsGroup = 'Hybrid Agent Extension Applications'
        HimdsServiceName = 'himds'
        HimdsPath = Join-Path $programFiles `
            'AzureConnectedMachineAgent\himds.exe'
        ArcProxyServiceName = 'ArcProxy'
        ArcProxyPath = Join-Path $programFiles `
            'AzureConnectedMachineAgent\arcproxy.exe'
    }
}

function Test-ArtifactSigningAzureArcSignedProgram {
    param([Parameter(Mandatory)][string] $Path)

    Assert-ArtifactSigningDirectPath -Path $Path -Directory $false
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ([string]$signature.Status -cne 'Valid' -or
        $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -cnotmatch
            '(?:^|, )CN=Microsoft (?:Corporation|Windows)') {
        throw 'ArtifactSigningAzureArcIdentityFailed:ProgramTrust'
    }
}

function Test-ArtifactSigningAzureArcServiceProgram {
    param(
        [Parameter(Mandatory)][string] $ServiceName,
        [Parameter(Mandatory)][string] $ExpectedPath
    )

    $null = Get-Service -Name $ServiceName -ErrorAction Stop
    $properties = Get-ItemProperty -LiteralPath (
        "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName")
    if ([string]$properties.ImagePath -cne ('"{0}"' -f $ExpectedPath) -or
        $properties.Start -ne 2) {
        throw 'ArtifactSigningAzureArcIdentityFailed:ServiceDefinition'
    }
    Test-ArtifactSigningAzureArcSignedProgram -Path $ExpectedPath
}

function Get-ArtifactSigningLocalGroupMemberSids {
    param([Parameter(Mandatory)] $Group)

    return @(
        Get-LocalGroupMember -Group $Group -ErrorAction Stop |
            ForEach-Object { [string]$_.SID.Value })
}

function Remove-ArtifactSigningLocalGroupMemberBySid {
    param(
        [Parameter(Mandatory)] $Group,
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier] $Sid
    )

    $matches = @(
        Get-LocalGroupMember -Group $Group -ErrorAction Stop |
            Where-Object {
                $null -ne $_.SID -and $_.SID.Value -ceq $Sid.Value
            })
    if ($matches.Count -eq 0) {
        return
    }
    if ($matches.Count -ne 1) {
        throw 'A local-group SID resolved ambiguously.'
    }
    Remove-LocalGroupMember -Group $Group `
        -Member $matches[0] -Confirm:$false
}

function Add-ArtifactSigningLocalGroupMemberBySid {
    param(
        [Parameter(Mandatory)] $Group,
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier] $Sid
    )

    $account = $Sid.Translate([Security.Principal.NTAccount])
    Add-LocalGroupMember -Group $Group -Member $account.Value
}

function Set-ArtifactSigningAzureArcIdentityAccess {
    param(
        [Parameter(Mandatory)] $Deployment,
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier] $GatewaySid,
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier] $WorkerSid
    )

    $policy = Get-ArtifactSigningAzureArcPolicy
    $group = Get-LocalGroup -Name $policy.HybridApplicationsGroup `
        -ErrorAction SilentlyContinue
    if (-not $Deployment.IsMicrosoftArtifactSigning) {
        if ($null -ne $group) {
            $members = @(Get-ArtifactSigningLocalGroupMemberSids `
                -Group $group)
            foreach ($serviceSid in @($GatewaySid, $WorkerSid)) {
                if ($members -ccontains $serviceSid.Value) {
                    Remove-ArtifactSigningLocalGroupMemberBySid `
                        -Group $group -Sid $serviceSid
                }
            }
        }
        return
    }

    if ($null -eq $group) {
        throw 'ArtifactSigningAzureArcIdentityFailed:HybridGroup'
    }
    Test-ArtifactSigningAzureArcServiceProgram `
        -ServiceName $policy.HimdsServiceName `
        -ExpectedPath $policy.HimdsPath
    Test-ArtifactSigningAzureArcServiceProgram `
        -ServiceName $policy.ArcProxyServiceName `
        -ExpectedPath $policy.ArcProxyPath

    $members = @(Get-ArtifactSigningLocalGroupMemberSids -Group $group)
    if ($members -ccontains $GatewaySid.Value) {
        Remove-ArtifactSigningLocalGroupMemberBySid `
            -Group $group -Sid $GatewaySid
    }
    if ($members -cnotcontains $WorkerSid.Value) {
        Add-ArtifactSigningLocalGroupMemberBySid `
            -Group $group -Sid $WorkerSid
    }
    $builtIn = Get-ArtifactSigningBuiltInSids
    $administrators = Get-LocalGroup -SID $builtIn.Administrators `
        -ErrorAction Stop
    $administratorMembers = @(
        Get-ArtifactSigningLocalGroupMemberSids -Group $administrators)
    if ($administratorMembers -ccontains $WorkerSid.Value) {
        Remove-ArtifactSigningLocalGroupMemberBySid `
            -Group $administrators -Sid $WorkerSid
    }
    if ((Get-Service -Name $policy.HimdsServiceName).Status -ne 'Running') {
        Start-Service -Name $policy.HimdsServiceName
    }
    Test-ArtifactSigningAzureArcIdentityAccess `
        -Deployment $Deployment `
        -GatewaySid $GatewaySid `
        -WorkerSid $WorkerSid
}

function Test-ArtifactSigningAzureArcIdentityAccess {
    param(
        [Parameter(Mandatory)] $Deployment,
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier] $GatewaySid,
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier] $WorkerSid
    )

    if (-not $Deployment.IsMicrosoftArtifactSigning) {
        return
    }
    try {
        $policy = Get-ArtifactSigningAzureArcPolicy
        Test-ArtifactSigningAzureArcServiceProgram `
            -ServiceName $policy.HimdsServiceName `
            -ExpectedPath $policy.HimdsPath
        Test-ArtifactSigningAzureArcServiceProgram `
            -ServiceName $policy.ArcProxyServiceName `
            -ExpectedPath $policy.ArcProxyPath
        if ((Get-Service -Name $policy.HimdsServiceName).Status -ne
                'Running') {
            throw 'HimdsStatus'
        }
        $group = Get-LocalGroup -Name $policy.HybridApplicationsGroup `
            -ErrorAction Stop
        $members = @(Get-ArtifactSigningLocalGroupMemberSids -Group $group)
        $builtIn = Get-ArtifactSigningBuiltInSids
        $administrators = Get-LocalGroup -SID $builtIn.Administrators `
            -ErrorAction Stop
        $administratorMembers = @(
            Get-ArtifactSigningLocalGroupMemberSids -Group $administrators)
        if ($members -cnotcontains $WorkerSid.Value -or
            $members -ccontains $GatewaySid.Value -or
            $administratorMembers -ccontains $WorkerSid.Value) {
            throw 'Membership'
        }
    }
    catch {
        if ([string]$_.Exception.Message -cmatch
                '^ArtifactSigningAzureArcIdentityFailed:') {
            throw
        }
        throw 'ArtifactSigningAzureArcIdentityFailed:Validation'
    }
}

function Remove-ArtifactSigningAzureArcIdentityAccess {
    $policy = Get-ArtifactSigningAzureArcPolicy
    $group = Get-LocalGroup -Name $policy.HybridApplicationsGroup `
        -ErrorAction SilentlyContinue
    if ($null -eq $group) {
        return
    }
    foreach ($serviceName in @(
            $script:GatewayServiceName,
            $script:WorkerServiceName)) {
        if ($null -eq (Get-Service -Name $serviceName `
                -ErrorAction SilentlyContinue)) {
            continue
        }
        try {
            $serviceSid = Get-ArtifactSigningServiceSid `
                -ServiceName $serviceName
            $members = @(Get-ArtifactSigningLocalGroupMemberSids `
                -Group $group)
            if ($members -ccontains $serviceSid.Value) {
                Remove-ArtifactSigningLocalGroupMemberBySid `
                    -Group $group -Sid $serviceSid
            }
        }
        catch [Security.Principal.IdentityNotMappedException] {
        }
    }
}

function Install-ArtifactSigningServiceDefinitions {
    param(
        [Parameter(Mandatory)] $Paths,
        [Parameter(Mandatory)] $Deployment
    )

    $workerImage = '"{0}"' -f (
        Join-Path $Paths.WorkerRoot 'ArtifactSigning.Worker.exe')
    $gatewayImage = '"{0}"' -f (
        Join-Path $Paths.GatewayRoot 'ArtifactSigning.Gateway.exe')
    Invoke-ArtifactSigningServiceDefinitionOperation `
        -Operation WorkerCreate -Arguments @(
        'create', $script:WorkerServiceName,
        'binPath=', $workerImage,
        'start=', 'disabled',
        'depend=', ([string]::Join(
            '/',
            @(Get-ArtifactSigningWorkerServiceDependencies `
                -Deployment $Deployment))),
        'DisplayName=', 'Artifact Signing Worker'
    )
    Invoke-ArtifactSigningServiceDefinitionOperation `
        -Operation WorkerIdentity -Arguments @(
        'config', $script:WorkerServiceName,
        'obj=', "NT SERVICE\$($script:WorkerServiceName)"
    )
    Invoke-ArtifactSigningServiceDefinitionOperation `
        -Operation WorkerStartMode -Arguments @(
        'config', $script:WorkerServiceName,
        'start=', 'delayed-auto'
    )
    Invoke-ArtifactSigningServiceDefinitionOperation `
        -Operation WorkerSidType -Arguments @(
        'sidtype', $script:WorkerServiceName, 'unrestricted'
    )
    Invoke-ArtifactSigningServiceDefinitionOperation `
        -Operation WorkerRecoveryActions -Arguments @(
        'failure', $script:WorkerServiceName,
        'reset=', '86400',
        'actions=', 'restart/5000/restart/15000/none/0'
    )
    Invoke-ArtifactSigningServiceDefinitionOperation `
        -Operation WorkerRecoveryFlag -Arguments @(
        'failureflag', $script:WorkerServiceName, '1'
    )

    Invoke-ArtifactSigningServiceDefinitionOperation `
        -Operation GatewayCreate -Arguments @(
        'create', $script:GatewayServiceName,
        'binPath=', $gatewayImage,
        'start=', 'disabled',
        'depend=', $script:WorkerServiceName,
        'DisplayName=', 'Artifact Signing Gateway'
    )
    Invoke-ArtifactSigningServiceDefinitionOperation `
        -Operation GatewayIdentity -Arguments @(
        'config', $script:GatewayServiceName,
        'obj=', "NT SERVICE\$($script:GatewayServiceName)"
    )
    Invoke-ArtifactSigningServiceDefinitionOperation `
        -Operation GatewayStartMode -Arguments @(
        'config', $script:GatewayServiceName,
        'start=', 'delayed-auto'
    )
    Invoke-ArtifactSigningServiceDefinitionOperation `
        -Operation GatewaySidType -Arguments @(
        'sidtype', $script:GatewayServiceName, 'unrestricted'
    )
    Invoke-ArtifactSigningServiceDefinitionOperation `
        -Operation GatewayRecoveryActions -Arguments @(
        'failure', $script:GatewayServiceName,
        'reset=', '86400',
        'actions=', 'restart/5000/restart/15000/none/0'
    )
    Invoke-ArtifactSigningServiceDefinitionOperation `
        -Operation GatewayRecoveryFlag -Arguments @(
        'failureflag', $script:GatewayServiceName, '1'
    )
}

function Stop-ArtifactSigningServices {
    foreach ($name in @(
            $script:GatewayServiceName,
            $script:WorkerServiceName)) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($null -ne $service -and $service.Status -ne 'Stopped') {
            Stop-Service -Name $name -Force
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        }
    }
}

function Remove-ArtifactSigningServiceDefinitions {
    Stop-ArtifactSigningServices
    foreach ($name in @(
            $script:GatewayServiceName,
            $script:WorkerServiceName)) {
        if ($null -ne (
                Get-Service -Name $name -ErrorAction SilentlyContinue)) {
            Invoke-ArtifactSigningSc @('delete', $name)
        }
    }
}

function Test-ArtifactSigningServiceDefinitions {
    param(
        [Parameter(Mandatory)] $Paths,
        [Parameter(Mandatory)] $Deployment
    )

    $expected = @{
        $script:WorkerServiceName = @{
            ImagePath = '"{0}"' -f (
                Join-Path $Paths.WorkerRoot 'ArtifactSigning.Worker.exe')
            ObjectName = "NT SERVICE\$($script:WorkerServiceName)"
            Dependencies = @(
                Get-ArtifactSigningWorkerServiceDependencies `
                    -Deployment $Deployment)
        }
        $script:GatewayServiceName = @{
            ImagePath = '"{0}"' -f (
                Join-Path $Paths.GatewayRoot 'ArtifactSigning.Gateway.exe')
            ObjectName = "NT SERVICE\$($script:GatewayServiceName)"
            Dependencies = @($script:WorkerServiceName)
        }
    }
    foreach ($name in $expected.Keys) {
        $null = Get-Service -Name $name -ErrorAction Stop
        $registryPath =
            "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
        $properties = Get-ItemProperty -LiteralPath $registryPath
        $dependencyProperty =
            $properties.PSObject.Properties['DependOnService']
        $dependencyFailure =
            'ArtifactSigningServiceDefinitionValidationFailed:GatewayDependency'
        if ($name -ceq $script:WorkerServiceName) {
            $dependencyFailure =
                'ArtifactSigningServiceDefinitionValidationFailed:WorkerDependency'
        }
        if ($expected[$name].Dependencies.Count -eq 0) {
            if ($null -ne $dependencyProperty) {
                throw $dependencyFailure
            }
        }
        else {
            try {
                $dependencies = @()
                if ($null -ne $dependencyProperty) {
                    $dependencies = @($dependencyProperty.Value)
                }
            }
            catch {
                throw $dependencyFailure
            }
            if ($dependencies.Count -ne
                    $expected[$name].Dependencies.Count -or
                [string]::Join(
                    "`n",
                    @($dependencies | Sort-Object)) -cne
                [string]::Join(
                    "`n",
                    @($expected[$name].Dependencies | Sort-Object))) {
                throw $dependencyFailure
            }
        }

        $imagePathFailure =
            'ArtifactSigningServiceDefinitionValidationFailed:GatewayImagePath'
        if ($name -ceq $script:WorkerServiceName) {
            $imagePathFailure =
                'ArtifactSigningServiceDefinitionValidationFailed:WorkerImagePath'
        }
        try {
            $imagePathProperty =
                $properties.PSObject.Properties['ImagePath']
            if ($null -eq $imagePathProperty -or
                [string]$imagePathProperty.Value -cne
                    $expected[$name].ImagePath) {
                throw $imagePathFailure
            }
        }
        catch {
            throw $imagePathFailure
        }

        if ($properties.ObjectName -cne $expected[$name].ObjectName -or
            $properties.Start -ne 2 -or
            $properties.DelayedAutoStart -ne 1 -or
            $properties.ServiceSidType -ne 1 -or
            $properties.FailureActionsOnNonCrashFailures -ne 1 -or
            $null -eq $properties.FailureActions) {
            throw 'An installed Windows service definition is invalid.'
        }
    }
}

function Resolve-ArtifactSigningPrivateKeyFile {
    param([Parameter(Mandatory)][string] $Thumbprint)

    $stage = 'CertificateSelection'
    $store = $null
    $certificates = @()
    $rsa = $null
    try {
        $store = [Security.Cryptography.X509Certificates.X509Store]::new(
            [Security.Cryptography.X509Certificates.StoreName]::My,
            [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
        $store.Open(
            [Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        $certificates = @($store.Certificates.Find(
            [Security.Cryptography.X509Certificates.X509FindType]::
                FindByThumbprint,
            $Thumbprint,
            $false))
        if ($certificates.Count -ne 1 -or
            -not $certificates[0].HasPrivateKey) {
            throw 'An installed certificate is missing or ambiguous.'
        }

        $stage = 'PrivateKeyOpen'
        $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificates[0])
        if ($rsa -isnot [Security.Cryptography.RSACng]) {
            throw 'An installed private key is not a CNG RSA key.'
        }

        $stage = 'PrivateKeyPolicy'
        $key = $rsa.Key
        if (-not $key.IsMachineKey -or $key.IsEphemeral -or
            $key.Provider.Provider -cne
                'Microsoft Software Key Storage Provider' -or
            $key.ExportPolicy -ne
                [Security.Cryptography.CngExportPolicies]::None -or
            $key.UniqueName -cnotmatch '^[A-Za-z0-9_-]{1,128}$') {
            throw 'An installed private key is not a non-exportable machine key.'
        }

        $stage = 'PrivateKeyPath'
        $programData = [Environment]::GetFolderPath(
            [Environment+SpecialFolder]::CommonApplicationData)
        $keyPath = Join-Path (
            Join-Path $programData 'Microsoft\Crypto\Keys'
        ) $key.UniqueName
        Assert-ArtifactSigningDirectPath `
            -Path $keyPath -Directory $false
        return $keyPath
    }
    catch {
        throw "ArtifactSigningPrivateKeyResolutionFailed:$stage"
    }
    finally {
        if ($null -ne $rsa) {
            $rsa.Dispose()
        }
        foreach ($certificate in $certificates) {
            $certificate.Dispose()
        }
        if ($null -ne $store) {
            $store.Dispose()
        }
    }
}

function Resolve-ArtifactSigningKeyAclPrivateKeyFile {
    param(
        [Parameter(Mandatory)][string] $Thumbprint,
        [Parameter(Mandatory)]
        [ValidateSet('GatewayTls', 'Receipt', 'Authenticode')]
        [string] $Role
    )

    try {
        return Resolve-ArtifactSigningPrivateKeyFile -Thumbprint $Thumbprint
    }
    catch {
        $stage = 'Resolution'
        if ([string]$_.Exception.Message -cmatch (
                '^ArtifactSigningPrivateKeyResolutionFailed:' +
                '(CertificateSelection|PrivateKeyOpen|' +
                'PrivateKeyPolicy|PrivateKeyPath)$')) {
            $stage = $Matches[1]
        }

        throw "ArtifactSigningKeyAclFailed:$Role$stage"
    }
}

function Set-ArtifactSigningKeyAcls {
    param(
        [Parameter(Mandatory)] $Deployment,
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier] $GatewaySid,
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier] $WorkerSid
    )

    $builtIn = Get-ArtifactSigningBuiltInSids
    $tlsKey = Resolve-ArtifactSigningKeyAclPrivateKeyFile `
        -Thumbprint $Deployment.Values.GatewayTlsCertificateThumbprint `
        -Role GatewayTls
    $receiptKey = Resolve-ArtifactSigningKeyAclPrivateKeyFile `
        -Thumbprint $Deployment.Values.ReceiptCertificateThumbprint `
        -Role Receipt
    $keyPaths = @($tlsKey, $receiptKey)
    $signingKey = $null
    if (-not $Deployment.IsMicrosoftArtifactSigning) {
        $signingKey = Resolve-ArtifactSigningKeyAclPrivateKeyFile `
            -Thumbprint $Deployment.Values.AuthenticodeCertificateThumbprint `
            -Role Authenticode
        $keyPaths += $signingKey
    }
    $keyCount = @(
        $keyPaths |
            Sort-Object -Unique
    ).Count
    if ($keyCount -ne $keyPaths.Count) {
        throw 'ArtifactSigningKeyAclFailed:Distinctness'
    }

    try {
        Set-ArtifactSigningExactAcl -Path $tlsKey `
            -FullControl @(
                $builtIn.System,
                $builtIn.Administrators,
                $GatewaySid
            ) -ReadAndExecute @() -Directory $false
    }
    catch {
        throw 'ArtifactSigningKeyAclFailed:GatewayTlsWrite'
    }
    try {
        Set-ArtifactSigningExactAcl -Path $receiptKey `
            -FullControl @(
                $builtIn.System,
                $builtIn.Administrators,
                $WorkerSid
            ) -ReadAndExecute @() -Directory $false
    }
    catch {
        throw 'ArtifactSigningKeyAclFailed:ReceiptWrite'
    }
    if ($null -ne $signingKey) {
        try {
            Set-ArtifactSigningExactAcl -Path $signingKey `
                -FullControl @(
                    $builtIn.System,
                    $builtIn.Administrators,
                    $WorkerSid
                ) -ReadAndExecute @() -Directory $false
        }
        catch {
            throw 'ArtifactSigningKeyAclFailed:AuthenticodeWrite'
        }
    }
}

function Test-ArtifactSigningKeyAcls {
    param(
        [Parameter(Mandatory)] $Deployment,
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier] $GatewaySid,
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier] $WorkerSid
    )

    $builtIn = Get-ArtifactSigningBuiltInSids
    $tlsKey = Resolve-ArtifactSigningPrivateKeyFile `
        -Thumbprint $Deployment.Values.GatewayTlsCertificateThumbprint
    Test-ArtifactSigningExactAcl -Path $tlsKey `
        -FullControl @(
            $builtIn.System,
            $builtIn.Administrators,
            $GatewaySid
        ) -ReadAndExecute @() -Directory $false
    $workerKeyThumbprints = @(
        $Deployment.Values.ReceiptCertificateThumbprint)
    if (-not $Deployment.IsMicrosoftArtifactSigning) {
        $workerKeyThumbprints +=
            $Deployment.Values.AuthenticodeCertificateThumbprint
    }
    foreach ($thumbprint in $workerKeyThumbprints) {
        $keyPath = Resolve-ArtifactSigningPrivateKeyFile `
            -Thumbprint $thumbprint
        Test-ArtifactSigningExactAcl -Path $keyPath `
            -FullControl @(
                $builtIn.System,
                $builtIn.Administrators,
                $WorkerSid
            ) -ReadAndExecute @() -Directory $false
    }
}

function Expand-ArtifactSigningConfigurationTemplates {
    param(
        [Parameter(Mandatory)][string] $PackageRoot,
        [Parameter(Mandatory)] $Paths,
        [Parameter(Mandatory)] $Deployment,
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier] $GatewaySid,
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier] $WorkerSid
    )

    $dlibPath = Join-Path $Paths.WorkerRoot `
        'MicrosoftArtifactSigningClient\Azure.CodeSigning.Dlib.dll'
    $trustedPublisherRootsJson = '[' + [string]::Join(
        ',',
        @($Deployment.MicrosoftArtifactSigningTrustedPublisherRootThumbprints |
            ForEach-Object { '"{0}"' -f $_ })) + ']'
    $timestampUrl = if ($Deployment.IsMicrosoftArtifactSigning) {
        ''
    }
    else {
        "http://$($Deployment.TimestampRelayAddress):$($Deployment.TimestampRelayPort)/timestamp"
    }
    $replacements = [ordered]@{
        '__GATEWAY_SERVICE_SID__' = $GatewaySid.Value
        '__WORKER_SERVICE_SID__' = $WorkerSid.Value
        '__GATEWAY_LISTEN_ADDRESS__' =
            $Deployment.GatewayListenAddress
        '__GATEWAY_LISTEN_PORT__' =
            $Deployment.GatewayListenPort.ToString(
                [Globalization.CultureInfo]::InvariantCulture)
        '__GATEWAY_TLS_THUMBPRINT__' =
            $Deployment.Values.GatewayTlsCertificateThumbprint
        '__PROFILE_SET_SHA256__' =
            $Deployment.Values.ProfileSetSha256
        '__RECEIPT_THUMBPRINT__' =
            $Deployment.Values.ReceiptCertificateThumbprint
        '__SIGNING_PROVIDER__' = $Deployment.SigningProvider
        '__AUTHENTICODE_THUMBPRINT__' =
            $Deployment.Values.AuthenticodeCertificateThumbprint
        '__SIGNTOOL_PATH_JSON__' = (
            $Deployment.Values.SignToolPath.Replace('\', '\\'))
        '__SIGNTOOL_SHA256__' =
            $Deployment.Values.SignToolSha256
        '__SIGNTOOL_FILE_VERSION__' =
            $Deployment.Values.SignToolFileVersion
        '__TIMESTAMP_URL__' = $timestampUrl
        '__MICROSOFT_ARTIFACT_SIGNING_REGION__' =
            $Deployment.Values.MicrosoftArtifactSigningRegion
        '__MICROSOFT_ARTIFACT_SIGNING_ACCOUNT_NAME__' =
            $Deployment.Values.MicrosoftArtifactSigningAccountName
        '__MICROSOFT_ARTIFACT_SIGNING_CERTIFICATE_PROFILE_NAME__' =
            $Deployment.Values.MicrosoftArtifactSigningCertificateProfileName
        '__MICROSOFT_ARTIFACT_SIGNING_DLIB_PATH_JSON__' =
            $dlibPath.Replace('\', '\\')
        '__MICROSOFT_ARTIFACT_SIGNING_DLIB_SHA256__' =
            $Deployment.Values.MicrosoftArtifactSigningDlibSha256
        '__MICROSOFT_ARTIFACT_SIGNING_DLIB_FILE_VERSION__' =
            $Deployment.Values.MicrosoftArtifactSigningDlibFileVersion
        '__MICROSOFT_ARTIFACT_SIGNING_CLIENT_TOOLS_INVENTORY_SHA256__' =
            $Deployment.Values.MicrosoftArtifactSigningClientToolsInventorySha256
        '__MICROSOFT_ARTIFACT_SIGNING_EXPECTED_PUBLISHER_SUBJECT_NAME_SHA256__' =
            $Deployment.Values.MicrosoftArtifactSigningExpectedPublisherSubjectNameSha256
        '__MICROSOFT_ARTIFACT_SIGNING_REQUIRED_PUBLISHER_EKU_OID__' =
            $Deployment.Values.MicrosoftArtifactSigningRequiredPublisherEnhancedKeyUsageOid
        '__MICROSOFT_ARTIFACT_SIGNING_TRUSTED_PUBLISHER_ROOTS_JSON__' =
            $trustedPublisherRootsJson
        '__MICROSOFT_ARTIFACT_SIGNING_SIGNTOOL_TIMEOUT_SECONDS__' =
            $Deployment.MicrosoftArtifactSigningSignToolTimeoutSeconds.ToString(
                [Globalization.CultureInfo]::InvariantCulture)
        '__MICROSOFT_ARTIFACT_SIGNING_AUTHENTICODE_REVOCATION_POLICY__' =
            $Deployment.Values.MicrosoftArtifactSigningAuthenticodeRevocationPolicy
    }
    foreach ($definition in @(
        @{
            Source = Join-Path $PackageRoot `
                'config\gateway.template.json'
            Target = Join-Path $Paths.GatewayRoot 'gateway.json'
            Required = @(
                '__GATEWAY_SERVICE_SID__',
                '__WORKER_SERVICE_SID__',
                '__GATEWAY_LISTEN_ADDRESS__',
                '__GATEWAY_LISTEN_PORT__',
                '__GATEWAY_TLS_THUMBPRINT__',
                '__PROFILE_SET_SHA256__'
            )
        },
        @{
            Source = Join-Path $PackageRoot `
                'config\worker.template.json'
            Target = Join-Path $Paths.WorkerRoot 'worker.json'
            Required = if ($Deployment.IsMicrosoftArtifactSigning) {
                @(
                    '__GATEWAY_SERVICE_SID__',
                    '__WORKER_SERVICE_SID__',
                    '__RECEIPT_THUMBPRINT__',
                    '__SIGNING_PROVIDER__',
                    '__SIGNTOOL_PATH_JSON__',
                    '__SIGNTOOL_SHA256__',
                    '__SIGNTOOL_FILE_VERSION__',
                    '__MICROSOFT_ARTIFACT_SIGNING_REGION__',
                    '__MICROSOFT_ARTIFACT_SIGNING_ACCOUNT_NAME__',
                    '__MICROSOFT_ARTIFACT_SIGNING_CERTIFICATE_PROFILE_NAME__',
                    '__MICROSOFT_ARTIFACT_SIGNING_DLIB_PATH_JSON__',
                    '__MICROSOFT_ARTIFACT_SIGNING_DLIB_SHA256__',
                    '__MICROSOFT_ARTIFACT_SIGNING_DLIB_FILE_VERSION__',
                    '__MICROSOFT_ARTIFACT_SIGNING_CLIENT_TOOLS_INVENTORY_SHA256__',
                    '__MICROSOFT_ARTIFACT_SIGNING_EXPECTED_PUBLISHER_SUBJECT_NAME_SHA256__',
                    '__MICROSOFT_ARTIFACT_SIGNING_REQUIRED_PUBLISHER_EKU_OID__',
                    '__MICROSOFT_ARTIFACT_SIGNING_TRUSTED_PUBLISHER_ROOTS_JSON__',
                    '__MICROSOFT_ARTIFACT_SIGNING_SIGNTOOL_TIMEOUT_SECONDS__',
                    '__MICROSOFT_ARTIFACT_SIGNING_AUTHENTICODE_REVOCATION_POLICY__',
                    '__PROFILE_SET_SHA256__'
                )
            }
            else {
                @(
                '__GATEWAY_SERVICE_SID__',
                '__WORKER_SERVICE_SID__',
                '__RECEIPT_THUMBPRINT__',
                '__AUTHENTICODE_THUMBPRINT__',
                '__SIGNTOOL_PATH_JSON__',
                '__SIGNTOOL_SHA256__',
                '__SIGNTOOL_FILE_VERSION__',
                '__TIMESTAMP_URL__',
                '__PROFILE_SET_SHA256__'
                )
            }
        })) {
        $bytes = [IO.File]::ReadAllBytes($definition.Source)
        if ($bytes.Length -lt 1 -or $bytes.Length -gt 131072) {
            throw 'An installed configuration template is invalid.'
        }

        $text = [Text.UTF8Encoding]::new(
            $false,
            $true).GetString($bytes)
        foreach ($required in $definition.Required) {
            if (([regex]::Matches(
                        $text,
                        [regex]::Escape($required))).Count -ne 1) {
                throw 'An installed configuration template has a missing or duplicate required placeholder.'
            }
        }
        foreach ($replacement in $replacements.GetEnumerator()) {
            $count = (
                [regex]::Matches(
                    $text,
                    [regex]::Escape($replacement.Key))
            ).Count
            if ($count -gt 0) {
                $text = $text.Replace(
                    $replacement.Key,
                    [string]$replacement.Value)
            }
        }
        if ($text -cmatch '__[A-Z0-9_]+__') {
            throw 'An installed configuration has an unresolved placeholder.'
        }

        [IO.File]::WriteAllText(
            $definition.Target,
            $text,
            [Text.UTF8Encoding]::new($false))
    }
}

function Copy-ArtifactSigningReleasePayload {
    param(
        [Parameter(Mandatory)][string] $PackageRoot,
        [Parameter(Mandatory)] $Paths,
        [Parameter(Mandatory)][object[]] $Inventory
    )

    foreach ($root in @(
            $Paths.InstallRoot,
            $Paths.GatewayRoot,
            $Paths.WorkerRoot,
            $Paths.InstallerRoot)) {
        if (-not (Test-Path -LiteralPath $root)) {
            [IO.Directory]::CreateDirectory($root) | Out-Null
        }
        Assert-ArtifactSigningDirectPath -Path $root -Directory $true
    }

    foreach ($entry in $Inventory) {
        if ($entry.RelativePath -cmatch '^(Gateway|Worker|installer)/') {
            $destination = Join-Path $Paths.InstallRoot (
                $entry.RelativePath.Replace(
                    '/',
                    [IO.Path]::DirectorySeparatorChar))
            $parent = Split-Path -Parent $destination
            if (-not (Test-Path -LiteralPath $parent)) {
                [IO.Directory]::CreateDirectory($parent) | Out-Null
            }
            [IO.File]::Copy($entry.FullPath, $destination, $false)
        }
    }
}

function Set-ArtifactSigningInstallationAcls {
    param(
        [Parameter(Mandatory)] $Paths,
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier] $GatewaySid,
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier] $WorkerSid
    )

    $builtIn = Get-ArtifactSigningBuiltInSids
    $admins = @($builtIn.System, $builtIn.Administrators)
    Set-ArtifactSigningExactAcl -Path $Paths.InstallRoot `
        -FullControl $admins `
        -ReadAndExecute @($GatewaySid, $WorkerSid) `
        -Directory $true
    Set-ArtifactSigningExactAcl -Path $Paths.GatewayRoot `
        -FullControl $admins -ReadAndExecute @($GatewaySid) `
        -Directory $true
    Set-ArtifactSigningExactAcl -Path $Paths.WorkerRoot `
        -FullControl $admins -ReadAndExecute @($WorkerSid) `
        -Directory $true
    Set-ArtifactSigningExactAcl -Path $Paths.InstallerRoot `
        -FullControl $admins -ReadAndExecute @() -Directory $true

    foreach ($file in Get-ChildItem `
            -LiteralPath $Paths.GatewayRoot -File -Recurse -Force) {
        Set-ArtifactSigningExactAcl -Path $file.FullName `
            -FullControl $admins -ReadAndExecute @($GatewaySid) `
            -Directory $false
    }
    foreach ($file in Get-ChildItem `
            -LiteralPath $Paths.WorkerRoot -File -Recurse -Force) {
        Set-ArtifactSigningExactAcl -Path $file.FullName `
            -FullControl $admins -ReadAndExecute @($WorkerSid) `
            -Directory $false
    }
    foreach ($file in Get-ChildItem `
            -LiteralPath $Paths.InstallerRoot -File -Recurse -Force) {
        Set-ArtifactSigningExactAcl -Path $file.FullName `
            -FullControl $admins -ReadAndExecute @() -Directory $false
    }

    # Verify the native persisted descriptors before any later installation
    # phase can start a service or use a signing key.
    Test-ArtifactSigningInstallationAcls `
        -Paths $Paths `
        -GatewaySid $GatewaySid `
        -WorkerSid $WorkerSid
}

function Test-ArtifactSigningInstallationAclTarget {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier[]] $FullControl,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [Security.Principal.SecurityIdentifier[]] $ReadAndExecute,
        [Parameter(Mandatory)][bool] $Directory,
        [Parameter(Mandatory)]
        [ValidateSet(
            'InstallRoot',
            'GatewayRoot',
            'WorkerRoot',
            'InstallerRoot',
            'GatewayFiles',
            'WorkerFiles',
            'InstallerFiles')]
        [string] $Target
    )

    try {
        Test-ArtifactSigningExactAcl `
            -Path $Path `
            -FullControl $FullControl `
            -ReadAndExecute $ReadAndExecute `
            -Directory $Directory
    }
    catch {
        throw "ArtifactSigningInstallationAclFailed:$Target"
    }
}

function Test-ArtifactSigningInstallationAcls {
    param(
        [Parameter(Mandatory)] $Paths,
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier] $GatewaySid,
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier] $WorkerSid
    )

    $builtIn = Get-ArtifactSigningBuiltInSids
    $admins = @($builtIn.System, $builtIn.Administrators)
    Test-ArtifactSigningInstallationAclTarget -Path $Paths.InstallRoot `
        -FullControl $admins `
        -ReadAndExecute @($GatewaySid, $WorkerSid) `
        -Directory $true -Target InstallRoot
    Test-ArtifactSigningInstallationAclTarget -Path $Paths.GatewayRoot `
        -FullControl $admins -ReadAndExecute @($GatewaySid) `
        -Directory $true -Target GatewayRoot
    Test-ArtifactSigningInstallationAclTarget -Path $Paths.WorkerRoot `
        -FullControl $admins -ReadAndExecute @($WorkerSid) `
        -Directory $true -Target WorkerRoot
    Test-ArtifactSigningInstallationAclTarget -Path $Paths.InstallerRoot `
        -FullControl $admins -ReadAndExecute @() -Directory $true `
        -Target InstallerRoot
    foreach ($file in Get-ChildItem `
            -LiteralPath $Paths.GatewayRoot -File -Recurse -Force) {
        Test-ArtifactSigningInstallationAclTarget -Path $file.FullName `
            -FullControl $admins -ReadAndExecute @($GatewaySid) `
            -Directory $false -Target GatewayFiles
    }
    foreach ($file in Get-ChildItem `
            -LiteralPath $Paths.WorkerRoot -File -Recurse -Force) {
        Test-ArtifactSigningInstallationAclTarget -Path $file.FullName `
            -FullControl $admins -ReadAndExecute @($WorkerSid) `
            -Directory $false -Target WorkerFiles
    }
    foreach ($file in Get-ChildItem `
            -LiteralPath $Paths.InstallerRoot -File -Recurse -Force) {
        Test-ArtifactSigningInstallationAclTarget -Path $file.FullName `
            -FullControl $admins -ReadAndExecute @() -Directory $false `
            -Target InstallerFiles
    }
}

function New-ArtifactSigningStateDirectories {
    param(
        [Parameter(Mandatory)] $Paths,
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier] $GatewaySid,
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier] $WorkerSid
    )

    $builtIn = Get-ArtifactSigningBuiltInSids
    $admins = @($builtIn.System, $builtIn.Administrators)
    $definitions = @(
        @('', $admins, @($GatewaySid, $WorkerSid)),
        @('gateway-state', @($admins + $GatewaySid), @()),
        @('inbox', $admins, @($GatewaySid, $WorkerSid)),
        @('inbox\receiving', @($admins + $GatewaySid), @()),
        @('inbox\pending', @($admins + $GatewaySid), @()),
        @('inbox\ready', @($admins + $GatewaySid), @($WorkerSid)),
        @('worker-state', @($admins + $WorkerSid), @()),
        @('work', @($admins + $WorkerSid), @()),
        @('quarantine', @($admins + $WorkerSid), @()),
        @('output', @($admins + $WorkerSid), @($GatewaySid)),
        @('status', @($admins + $WorkerSid), @($GatewaySid))
    )
    foreach ($definition in $definitions) {
        $path = if ($definition[0].Length -eq 0) {
            $Paths.StateRoot
        }
        else {
            Join-Path $Paths.StateRoot $definition[0]
        }
        if (-not (Test-Path -LiteralPath $path)) {
            [IO.Directory]::CreateDirectory($path) | Out-Null
        }
        Set-ArtifactSigningExactAcl -Path $path `
            -FullControl $definition[1] `
            -ReadAndExecute $definition[2] `
            -Directory $true
    }
}

function Test-ArtifactSigningStateDirectories {
    param(
        [Parameter(Mandatory)] $Paths,
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier] $GatewaySid,
        [Parameter(Mandatory)]
        [Security.Principal.SecurityIdentifier] $WorkerSid
    )

    $builtIn = Get-ArtifactSigningBuiltInSids
    $admins = @($builtIn.System, $builtIn.Administrators)
    $definitions = @(
        @('', $admins, @($GatewaySid, $WorkerSid)),
        @('gateway-state', @($admins + $GatewaySid), @()),
        @('inbox', $admins, @($GatewaySid, $WorkerSid)),
        @('inbox\receiving', @($admins + $GatewaySid), @()),
        @('inbox\pending', @($admins + $GatewaySid), @()),
        @('inbox\ready', @($admins + $GatewaySid), @($WorkerSid)),
        @('worker-state', @($admins + $WorkerSid), @()),
        @('work', @($admins + $WorkerSid), @()),
        @('quarantine', @($admins + $WorkerSid), @()),
        @('output', @($admins + $WorkerSid), @($GatewaySid)),
        @('status', @($admins + $WorkerSid), @($GatewaySid))
    )
    foreach ($definition in $definitions) {
        $path = if ($definition[0].Length -eq 0) {
            $Paths.StateRoot
        }
        else {
            Join-Path $Paths.StateRoot $definition[0]
        }
        Test-ArtifactSigningExactAcl -Path $path `
            -FullControl $definition[1] `
            -ReadAndExecute $definition[2] `
            -Directory $true
    }
}

function Register-ArtifactSigningEventSources {
    foreach ($definition in Get-ArtifactSigningEventSourceDefinitions) {
        $source = $definition.Source
        $path =
            "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$source"
        if (-not (Test-Path -LiteralPath $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        New-ItemProperty -LiteralPath $path `
            -Name 'EventMessageFile' `
            -Value '%SystemRoot%\System32\EventCreate.exe' `
            -PropertyType ExpandString -Force | Out-Null
        New-ItemProperty -LiteralPath $path `
            -Name 'TypesSupported' -Value 7 `
            -PropertyType DWord -Force | Out-Null
    }

    Test-ArtifactSigningEventSources
}

function Unregister-ArtifactSigningEventSources {
    foreach ($definition in Get-ArtifactSigningEventSourceDefinitions) {
        $source = $definition.Source
        $path =
            "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$source"
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force
        }
    }
}

function Get-ArtifactSigningEventSourceDefinitions {
    return @(
        [pscustomobject]@{
            Source = $script:GatewayServiceName
            Target = 'Gateway'
        },
        [pscustomobject]@{
            Source = $script:WorkerServiceName
            Target = 'Worker'
        },
        [pscustomobject]@{
            Source = 'ArtifactSigningInstaller'
            Target = 'Installer'
        }
    )
}

function Test-ArtifactSigningEventSourceRegistryKey {
    param(
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryKey] $Key
    )

    $valueNames = @($Key.GetValueNames() | Sort-Object)
    if ($valueNames.Count -ne 2 -or
        [string]::Join("`n", $valueNames) -cne
            "EventMessageFile`nTypesSupported" -or
        $Key.GetValueKind('EventMessageFile') -ne
            [Microsoft.Win32.RegistryValueKind]::ExpandString -or
        [string]$Key.GetValue(
            'EventMessageFile',
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        ) -cne '%SystemRoot%\System32\EventCreate.exe' -or
        $Key.GetValueKind('TypesSupported') -ne
            [Microsoft.Win32.RegistryValueKind]::DWord -or
        [int]$Key.GetValue(
            'TypesSupported',
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        ) -ne 7) {
        throw 'An Artifact Signing Event Log source is invalid.'
    }
}

function Test-ArtifactSigningEventSources {
    foreach ($definition in Get-ArtifactSigningEventSourceDefinitions) {
        $key = $null
        try {
            $registryPath =
                'SYSTEM\CurrentControlSet\Services\EventLog\Application\' +
                $definition.Source
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                $registryPath,
                $false)
            if ($null -eq $key) {
                throw 'An Artifact Signing Event Log source is absent.'
            }
            Test-ArtifactSigningEventSourceRegistryKey -Key $key
        }
        catch {
            throw "ArtifactSigningEventSourceFailed:$($definition.Target)"
        }
        finally {
            if ($null -ne $key) {
                $key.Dispose()
            }
        }
    }
}

function Set-ArtifactSigningFirewallPolicy {
    param(
        [Parameter(Mandatory)] $Paths,
        [Parameter(Mandatory)] $Deployment
    )

    Remove-ArtifactSigningFirewallPolicy
    Set-NetFirewallProfile -Profile Domain,Private,Public `
        -DefaultInboundAction Block `
        -DefaultOutboundAction Block `
        -NotifyOnListen False `
        -AllowInboundRules True

    New-NetFirewallRule `
        -Name 'ArtifactSigning-Gateway-In' `
        -DisplayName 'Artifact Signing Gateway private mTLS ingress' `
        -Group 'Artifact Signing Appliance' `
        -Direction Inbound -Action Allow -Enabled True -Profile Any `
        -Protocol TCP `
        -LocalAddress $Deployment.GatewayListenAddress `
        -LocalPort $Deployment.GatewayListenPort `
        -RemoteAddress $Deployment.GatewayIngressRemoteAddresses `
        -Program (Join-Path $Paths.GatewayRoot `
            'ArtifactSigning.Gateway.exe') `
        -Service $script:GatewayServiceName | Out-Null

    if ($Deployment.IsMicrosoftArtifactSigning) {
        $arc = Get-ArtifactSigningAzureArcPolicy
        try {
            foreach ($dynamicKeyword in
                    $script:MicrosoftCertificateStatusDynamicKeywords) {
                New-NetFirewallDynamicKeywordAddress `
                    -Id $dynamicKeyword.Id `
                    -Keyword $dynamicKeyword.Fqdn `
                    -AutoResolve $true -ErrorAction Stop | Out-Null
            }
        }
        catch {
            throw 'ArtifactSigningFirewallPolicyFailed:' +
                'WorkerMicrosoftCertificateStatusKeywords'
        }
        New-NetFirewallRule `
            -Name 'ArtifactSigning-Worker-Himds-Loopback-Out' `
            -DisplayName 'Artifact Signing Worker Azure Arc identity endpoint' `
            -Group 'Artifact Signing Appliance' `
            -Direction Outbound -Action Allow -Enabled True -Profile Any `
            -Protocol TCP -RemoteAddress 127.0.0.1 -RemotePort 40342 `
            -Program (Join-Path $Paths.WorkerRoot `
                'ArtifactSigning.Worker.exe') `
            -Service $script:WorkerServiceName | Out-Null
        New-NetFirewallRule `
            -Name 'ArtifactSigning-SignTool-Himds-Loopback-Out' `
            -DisplayName 'Artifact Signing SignTool Azure Arc identity endpoint' `
            -Group 'Artifact Signing Appliance' `
            -Direction Outbound -Action Allow -Enabled True -Profile Any `
            -Protocol TCP -RemoteAddress 127.0.0.1 -RemotePort 40342 `
            -Program $Deployment.Values.SignToolPath | Out-Null
        New-NetFirewallRule `
            -Name 'ArtifactSigning-Worker-Microsoft-Out' `
            -DisplayName 'Artifact Signing SignTool managed signing and timestamp' `
            -Group 'Artifact Signing Appliance' `
            -Direction Outbound -Action Allow -Enabled True -Profile Any `
            -Protocol TCP -RemoteAddress Any -RemotePort 80,443 `
            -Program $Deployment.Values.SignToolPath | Out-Null
        New-NetFirewallRule `
            -Name 'ArtifactSigning-Worker-Microsoft-CertificateStatus-Out' `
            -DisplayName 'Artifact Signing Worker Microsoft certificate status' `
            -Group 'Artifact Signing Appliance' `
            -Direction Outbound -Action Allow -Enabled True -Profile Any `
            -Protocol TCP -RemotePort 80,443 `
            -RemoteDynamicKeywordAddresses @(
                $script:MicrosoftCertificateStatusDynamicKeywords.Id) `
            -Program (Join-Path $Paths.WorkerRoot `
                'ArtifactSigning.Worker.exe') `
            -Service $script:WorkerServiceName | Out-Null
        foreach ($arcService in @(
                @{
                    Name = 'Himds'
                    Path = $arc.HimdsPath
                    Service = $arc.HimdsServiceName
                },
                @{
                    Name = 'ArcProxy'
                    Path = $arc.ArcProxyPath
                    Service = $arc.ArcProxyServiceName
                })) {
            New-NetFirewallRule `
                -Name "ArtifactSigning-Arc-$($arcService.Name)-Out" `
                -DisplayName "Artifact Signing Azure Arc $($arcService.Name)" `
                -Group 'Artifact Signing Appliance' `
                -Direction Outbound -Action Allow -Enabled True -Profile Any `
                -Protocol TCP -RemoteAddress Any -RemotePort 443 `
                -Program $arcService.Path `
                -Service $arcService.Service | Out-Null
        }
        foreach ($protocol in @('UDP', 'TCP')) {
            New-NetFirewallRule `
                -Name "ArtifactSigning-Dns-$protocol-Out" `
                -DisplayName "Artifact Signing fixed DNS $protocol" `
                -Group 'Artifact Signing Appliance' `
                -Direction Outbound -Action Allow -Enabled True -Profile Any `
                -Protocol $protocol `
                -RemoteAddress $Deployment.DnsServerAddresses `
                -RemotePort 53 -Program System | Out-Null
        }
    }
    else {
        New-NetFirewallRule `
            -Name 'ArtifactSigning-Worker-Timestamp-Out' `
            -DisplayName 'Artifact Signing SignTool fixed timestamp relay' `
            -Group 'Artifact Signing Appliance' `
            -Direction Outbound -Action Allow -Enabled True -Profile Any `
            -Protocol TCP `
            -RemoteAddress $Deployment.TimestampRelayAddress `
            -RemotePort $Deployment.TimestampRelayPort `
            -Program $Deployment.Values.SignToolPath | Out-Null

        New-NetFirewallRule `
            -Name 'ArtifactSigning-Worker-Readiness-Out' `
            -DisplayName 'Artifact Signing Worker timestamp readiness' `
            -Group 'Artifact Signing Appliance' `
            -Direction Outbound -Action Allow -Enabled True -Profile Any `
            -Protocol TCP `
            -RemoteAddress $Deployment.TimestampRelayAddress `
            -RemotePort $Deployment.TimestampRelayPort `
            -Program (Join-Path $Paths.WorkerRoot `
                'ArtifactSigning.Worker.exe') `
            -Service $script:WorkerServiceName | Out-Null
    }

    if ($Deployment.CertificateStatusRemoteAddresses.Count -gt 0) {
        foreach ($service in @(
                @{
                    Name = 'Gateway'
                    Path = Join-Path $Paths.GatewayRoot `
                        'ArtifactSigning.Gateway.exe'
                    Service = $script:GatewayServiceName
                },
                @{
                    Name = 'Worker'
                    Path = Join-Path $Paths.WorkerRoot `
                        'ArtifactSigning.Worker.exe'
                    Service = $script:WorkerServiceName
                })) {
            New-NetFirewallRule `
                -Name "ArtifactSigning-$($service.Name)-Revocation-Out" `
                -DisplayName "Artifact Signing $($service.Name) certificate status" `
                -Group 'Artifact Signing Appliance' `
                -Direction Outbound -Action Allow -Enabled True -Profile Any `
                -Protocol TCP `
                -RemoteAddress $Deployment.CertificateStatusRemoteAddresses `
                -RemotePort 80,443 `
                -Program $service.Path `
                -Service $service.Service | Out-Null
        }
    }

    New-NetFirewallRule `
        -Name 'ArtifactSigning-Time-Out' `
        -DisplayName 'Artifact Signing fixed time synchronization' `
        -Group 'Artifact Signing Appliance' `
        -Direction Outbound -Action Allow -Enabled True -Profile Any `
        -Protocol UDP `
        -RemoteAddress $Deployment.TimeServerAddresses `
        -RemotePort 123 `
        -Service 'W32Time' | Out-Null

    # Verify the native persisted rule/filter representation before any later
    # installation phase can start the services.
    Test-ArtifactSigningFirewallPolicy `
        -Paths $Paths -Deployment $Deployment
}

function Remove-ArtifactSigningFirewallPolicy {
    Get-NetFirewallRule -Group 'Artifact Signing Appliance' `
        -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction Stop
    if ($null -ne (Get-Command `
            Remove-NetFirewallDynamicKeywordAddress `
            -ErrorAction SilentlyContinue)) {
        foreach ($dynamicKeyword in
                $script:MicrosoftCertificateStatusDynamicKeywords) {
            Remove-NetFirewallDynamicKeywordAddress `
                -Id $dynamicKeyword.Id `
                -Confirm:$false `
                -ErrorAction SilentlyContinue
        }
    }
}

function Test-ArtifactSigningMicrosoftCertificateStatusDynamicKeywords {
    foreach ($definition in
            $script:MicrosoftCertificateStatusDynamicKeywords) {
        try {
            $dynamicKeywords = @(Get-NetFirewallDynamicKeywordAddress `
                -Id $definition.Id -ErrorAction Stop)
            if ($dynamicKeywords.Count -ne 1 -or
                [string]$dynamicKeywords[0].Id -cne $definition.Id -or
                [string]$dynamicKeywords[0].Keyword -cne $definition.Fqdn -or
                [string]$dynamicKeywords[0].AutoResolve -cne 'True') {
                throw 'A Microsoft certificate-status keyword is invalid.'
            }
        }
        catch {
            throw 'ArtifactSigningFirewallPolicyFailed:' +
                'WorkerMicrosoftCertificateStatusKeywords'
        }
    }
}

function Test-ArtifactSigningFirewallPolicy {
    param(
        [Parameter(Mandatory)] $Paths,
        [Parameter(Mandatory)] $Deployment
    )

    try {
        $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
        if ($profiles.Count -ne 3 -or
            [string]::Join(
                "`n",
                @($profiles.Name | Sort-Object)) -cne
            "Domain`nPrivate`nPublic") {
            throw 'The appliance firewall profile set is invalid.'
        }
        foreach ($profile in $profiles) {
            if ([string]$profile.DefaultInboundAction -cne 'Block' -or
                [string]$profile.DefaultOutboundAction -cne 'Block' -or
                [string]$profile.NotifyOnListen -cne 'False' -or
                [string]$profile.AllowInboundRules -cne 'True') {
                throw 'The appliance default firewall policy is not deny-by-default.'
            }
        }
    }
    catch {
        throw 'ArtifactSigningFirewallPolicyFailed:Profiles'
    }

    $expectedNames = @(
        'ArtifactSigning-Gateway-In',
        'ArtifactSigning-Time-Out'
    )
    if ($Deployment.IsMicrosoftArtifactSigning) {
        Test-ArtifactSigningMicrosoftCertificateStatusDynamicKeywords
        $expectedNames += @(
            'ArtifactSigning-Worker-Himds-Loopback-Out',
            'ArtifactSigning-SignTool-Himds-Loopback-Out',
            'ArtifactSigning-Worker-Microsoft-Out',
            'ArtifactSigning-Worker-Microsoft-CertificateStatus-Out',
            'ArtifactSigning-Arc-Himds-Out',
            'ArtifactSigning-Arc-ArcProxy-Out',
            'ArtifactSigning-Dns-UDP-Out',
            'ArtifactSigning-Dns-TCP-Out'
        )
    }
    else {
        $expectedNames += @(
            'ArtifactSigning-Worker-Timestamp-Out',
            'ArtifactSigning-Worker-Readiness-Out'
        )
    }
    if ($Deployment.CertificateStatusRemoteAddresses.Count -gt 0) {
        $expectedNames += @(
            'ArtifactSigning-Gateway-Revocation-Out',
            'ArtifactSigning-Worker-Revocation-Out'
        )
    }
    try {
        $rules = @(Get-NetFirewallRule `
            -Group 'Artifact Signing Appliance' -ErrorAction Stop)
        $normalizedRules = @(
            foreach ($candidate in $rules) {
                [pscustomobject]@{
                    Name = [string]$candidate.Name
                    Enabled = [string]$candidate.Enabled
                    Action = [string]$candidate.Action
                    Profile = [string]$candidate.Profile
                }
            }
        )
        if ($normalizedRules.Count -ne $expectedNames.Count -or
            [string]::Join(
                "`n",
                @($normalizedRules.Name | Sort-Object)) -cne
            [string]::Join(
                "`n",
                @($expectedNames | Sort-Object))) {
            throw 'The appliance firewall rule set is invalid.'
        }
        foreach ($candidate in $normalizedRules) {
            if ($candidate.Enabled -cne 'True' -or
                $candidate.Action -cne 'Allow' -or
                $candidate.Profile -cne 'Any') {
                throw 'The appliance firewall rule set is invalid.'
            }
        }
    }
    catch {
        throw 'ArtifactSigningFirewallPolicyFailed:RuleSet'
    }

    $definitions = @(
        @{
            Name = 'ArtifactSigning-Gateway-In'
            Target = 'GatewayIn'
            Direction = 'Inbound'
            Protocol = 'TCP'
            LocalAddress = @($Deployment.GatewayListenAddress)
            LocalPort = @([string]$Deployment.GatewayListenPort)
            RemoteAddress =
                @($Deployment.GatewayIngressRemoteAddresses)
            RemotePort = @('Any')
            Program = Join-Path $Paths.GatewayRoot `
                'ArtifactSigning.Gateway.exe'
            Service = $script:GatewayServiceName
        },
        @{
            Name = 'ArtifactSigning-Time-Out'
            Target = 'Time'
            Direction = 'Outbound'
            Protocol = 'UDP'
            LocalAddress = @('Any')
            LocalPort = @('Any')
            RemoteAddress = @($Deployment.TimeServerAddresses)
            RemotePort = @('123')
            Program = 'Any'
            Service = 'W32Time'
        }
    )
    if ($Deployment.IsMicrosoftArtifactSigning) {
        $arc = Get-ArtifactSigningAzureArcPolicy
        $definitions += @(
            @{
                Name = 'ArtifactSigning-Worker-Himds-Loopback-Out'
                Target = 'WorkerHimdsLoopback'
                Direction = 'Outbound'
                Protocol = 'TCP'
                LocalAddress = @('Any')
                LocalPort = @('Any')
                RemoteAddress = @('127.0.0.1')
                RemotePort = @('40342')
                Program = Join-Path $Paths.WorkerRoot `
                    'ArtifactSigning.Worker.exe'
                Service = $script:WorkerServiceName
            },
            @{
                Name = 'ArtifactSigning-SignTool-Himds-Loopback-Out'
                Target = 'SignToolHimdsLoopback'
                Direction = 'Outbound'
                Protocol = 'TCP'
                LocalAddress = @('Any')
                LocalPort = @('Any')
                RemoteAddress = @('127.0.0.1')
                RemotePort = @('40342')
                Program = $Deployment.Values.SignToolPath
                Service = 'Any'
            },
            @{
                Name = 'ArtifactSigning-Worker-Microsoft-Out'
                Target = 'WorkerMicrosoft'
                Direction = 'Outbound'
                Protocol = 'TCP'
                LocalAddress = @('Any')
                LocalPort = @('Any')
                RemoteAddress = @('Any')
                RemotePort = @('80', '443')
                Program = $Deployment.Values.SignToolPath
                Service = 'Any'
            },
            @{
                Name = 'ArtifactSigning-Worker-Microsoft-CertificateStatus-Out'
                Target = 'WorkerMicrosoftCertificateStatus'
                Direction = 'Outbound'
                Protocol = 'TCP'
                LocalAddress = @('Any')
                LocalPort = @('Any')
                RemoteDynamicKeywordAddresses = @(
                    $script:MicrosoftCertificateStatusDynamicKeywords.Id)
                RemotePort = @('80', '443')
                Program = Join-Path $Paths.WorkerRoot `
                    'ArtifactSigning.Worker.exe'
                Service = $script:WorkerServiceName
            },
            @{
                Name = 'ArtifactSigning-Arc-Himds-Out'
                Target = 'ArcHimds'
                Direction = 'Outbound'
                Protocol = 'TCP'
                LocalAddress = @('Any')
                LocalPort = @('Any')
                RemoteAddress = @('Any')
                RemotePort = @('443')
                Program = $arc.HimdsPath
                Service = $arc.HimdsServiceName
            },
            @{
                Name = 'ArtifactSigning-Arc-ArcProxy-Out'
                Target = 'ArcProxy'
                Direction = 'Outbound'
                Protocol = 'TCP'
                LocalAddress = @('Any')
                LocalPort = @('Any')
                RemoteAddress = @('Any')
                RemotePort = @('443')
                Program = $arc.ArcProxyPath
                Service = $arc.ArcProxyServiceName
            },
            @{
                Name = 'ArtifactSigning-Dns-UDP-Out'
                Target = 'DnsUdp'
                Direction = 'Outbound'
                Protocol = 'UDP'
                LocalAddress = @('Any')
                LocalPort = @('Any')
                RemoteAddress = @($Deployment.DnsServerAddresses)
                RemotePort = @('53')
                Program = 'System'
                Service = 'Any'
            },
            @{
                Name = 'ArtifactSigning-Dns-TCP-Out'
                Target = 'DnsTcp'
                Direction = 'Outbound'
                Protocol = 'TCP'
                LocalAddress = @('Any')
                LocalPort = @('Any')
                RemoteAddress = @($Deployment.DnsServerAddresses)
                RemotePort = @('53')
                Program = 'System'
                Service = 'Any'
            }
        )
    }
    else {
        $definitions += @(
            @{
                Name = 'ArtifactSigning-Worker-Timestamp-Out'
                Target = 'WorkerTimestamp'
                Direction = 'Outbound'
                Protocol = 'TCP'
                LocalAddress = @('Any')
                LocalPort = @('Any')
                RemoteAddress = @($Deployment.TimestampRelayAddress)
                RemotePort = @([string]$Deployment.TimestampRelayPort)
                Program = $Deployment.Values.SignToolPath
                Service = 'Any'
            },
            @{
                Name = 'ArtifactSigning-Worker-Readiness-Out'
                Target = 'WorkerReadiness'
                Direction = 'Outbound'
                Protocol = 'TCP'
                LocalAddress = @('Any')
                LocalPort = @('Any')
                RemoteAddress = @($Deployment.TimestampRelayAddress)
                RemotePort = @([string]$Deployment.TimestampRelayPort)
                Program = Join-Path $Paths.WorkerRoot `
                    'ArtifactSigning.Worker.exe'
                Service = $script:WorkerServiceName
            }
        )
    }
    if ($Deployment.CertificateStatusRemoteAddresses.Count -gt 0) {
        $definitions += @(
            @{
                Name = 'ArtifactSigning-Gateway-Revocation-Out'
                Target = 'GatewayRevocation'
                Direction = 'Outbound'
                Protocol = 'TCP'
                LocalAddress = @('Any')
                LocalPort = @('Any')
                RemoteAddress =
                    @($Deployment.CertificateStatusRemoteAddresses)
                RemotePort = @('80', '443')
                Program = Join-Path $Paths.GatewayRoot `
                    'ArtifactSigning.Gateway.exe'
                Service = $script:GatewayServiceName
            },
            @{
                Name = 'ArtifactSigning-Worker-Revocation-Out'
                Target = 'WorkerRevocation'
                Direction = 'Outbound'
                Protocol = 'TCP'
                LocalAddress = @('Any')
                LocalPort = @('Any')
                RemoteAddress =
                    @($Deployment.CertificateStatusRemoteAddresses)
                RemotePort = @('80', '443')
                Program = Join-Path $Paths.WorkerRoot `
                    'ArtifactSigning.Worker.exe'
                Service = $script:WorkerServiceName
            }
        )
    }
    foreach ($definition in $definitions) {
        try {
            $matchingRules = @(Get-NetFirewallRule `
                -Name $definition.Name -ErrorAction Stop)
            if ($matchingRules.Count -ne 1) {
                throw 'An appliance firewall rule is ambiguous.'
            }
            $rule = $matchingRules[0]
            $ports = @($rule | Get-NetFirewallPortFilter `
                -ErrorAction Stop)
            $addresses = @($rule | Get-NetFirewallAddressFilter `
                -ErrorAction Stop)
            $applications = @($rule | Get-NetFirewallApplicationFilter `
                -ErrorAction Stop)
            $services = @($rule | Get-NetFirewallServiceFilter `
                -ErrorAction Stop)
            if ($ports.Count -ne 1 -or $addresses.Count -ne 1 -or
                $applications.Count -ne 1 -or $services.Count -ne 1) {
                throw 'An appliance firewall filter is ambiguous.'
            }
            $port = $ports[0]
            $address = $addresses[0]
            $application = $applications[0]
            $service = $services[0]
            $usesDynamicKeywords =
                $definition.ContainsKey('RemoteDynamicKeywordAddresses')
            $currentDynamicKeywords = @()
            if ($null -ne $rule.PSObject.Properties[
                    'RemoteDynamicKeywordAddresses'] -and
                $null -ne $rule.RemoteDynamicKeywordAddresses) {
                $currentDynamicKeywords = @(
                    $rule.RemoteDynamicKeywordAddresses |
                        Where-Object { -not [string]::IsNullOrEmpty($_) })
            }
            $expectedDynamicKeywords = if ($usesDynamicKeywords) {
                @($definition.RemoteDynamicKeywordAddresses)
            }
            else {
                @()
            }
            $remoteAddressMatches = $usesDynamicKeywords -or
                [string]::Join(
                    ',',
                    @($address.RemoteAddress | Sort-Object)) -ceq
                [string]::Join(
                    ',',
                    @($definition.RemoteAddress | Sort-Object))
            if ([string]$rule.Direction -cne $definition.Direction -or
                [string]$port.Protocol -cne $definition.Protocol -or
                [string]::Join(
                    ',',
                    @($port.LocalPort | Sort-Object)) -cne
                [string]::Join(
                    ',',
                    @($definition.LocalPort | Sort-Object)) -or
                [string]::Join(
                    ',',
                    @($port.RemotePort | Sort-Object)) -cne
                [string]::Join(
                    ',',
                    @($definition.RemotePort | Sort-Object)) -or
                [string]::Join(
                    ',',
                    @($address.LocalAddress | Sort-Object)) -cne
                [string]::Join(
                    ',',
                    @($definition.LocalAddress | Sort-Object)) -or
                -not $remoteAddressMatches -or
                [string]::Join(
                    ',',
                    @($currentDynamicKeywords | Sort-Object)) -cne
                [string]::Join(
                    ',',
                    @($expectedDynamicKeywords | Sort-Object)) -or
                [string]$application.Program -cne $definition.Program -or
                [string]$service.Service -cne $definition.Service) {
                throw 'An appliance firewall filter is invalid.'
            }
        }
        catch {
            throw "ArtifactSigningFirewallPolicyFailed:$($definition.Target)"
        }
    }
}

function Get-ArtifactSigningManualTimePeers {
    param([Parameter(Mandatory)] $Deployment)

    $addresses = @($Deployment.TimeServerAddresses)
    if ($addresses.Count -lt 1 -or $addresses.Count -gt 4) {
        throw 'ArtifactSigningTimePolicyFailed:PeerSet'
    }
    return [string]::Join(
        ' ',
        @($addresses | ForEach-Object { "$_,0x8" }))
}

function Test-ArtifactSigningTimePolicy {
    param([Parameter(Mandatory)] $Deployment)

    try {
        $expectedPeers = Get-ArtifactSigningManualTimePeers `
            -Deployment $Deployment
        $service = Get-Service -Name W32Time -ErrorAction Stop
        $serviceProperties = Get-ItemProperty -LiteralPath `
            'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time' `
            -ErrorAction Stop
        $parameters = Get-ItemProperty -LiteralPath `
            'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' `
            -ErrorAction Stop
        $client = Get-ItemProperty -LiteralPath `
            ('HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\' +
                'TimeProviders\NtpClient') `
            -ErrorAction Stop
        if ($service.Status -ne 'Running' -or
            [int]$serviceProperties.Start -ne 2 -or
            [string]$parameters.Type -cne 'NTP' -or
            [string]$parameters.NtpServer -cne $expectedPeers -or
            [int]$client.Enabled -ne 1) {
            throw 'The Windows Time configuration is invalid.'
        }
        Invoke-ArtifactSigningWindowsTime -Arguments @(
            '/resync', '/rediscover')
    }
    catch {
        throw 'ArtifactSigningTimePolicyFailed:Verification'
    }
}

function Set-ArtifactSigningTimePolicy {
    param([Parameter(Mandatory)] $Deployment)

    $stage = 'Service'
    try {
        $manualPeers = Get-ArtifactSigningManualTimePeers `
            -Deployment $Deployment
        Set-Service -Name W32Time -StartupType Automatic `
            -ErrorAction Stop
        $service = Get-Service -Name W32Time -ErrorAction Stop
        if ($service.Status -ne 'Running') {
            Start-Service -Name W32Time -ErrorAction Stop
            $service.WaitForStatus(
                'Running',
                [TimeSpan]::FromSeconds(30))
        }

        $stage = 'Configuration'
        Invoke-ArtifactSigningWindowsTime -Arguments @(
            '/config',
            "/manualpeerlist:$manualPeers",
            '/syncfromflags:manual',
            '/reliable:no',
            '/update')
        Restart-Service -Name W32Time -Force -ErrorAction Stop
        $service = Get-Service -Name W32Time -ErrorAction Stop
        $service.WaitForStatus(
            'Running',
            [TimeSpan]::FromSeconds(30))

        $stage = 'Synchronization'
        $synchronized = $false
        foreach ($attempt in 1..3) {
            try {
                Invoke-ArtifactSigningWindowsTime -Arguments @(
                    '/resync', '/rediscover')
                $synchronized = $true
                break
            }
            catch {
                if ($attempt -lt 3) {
                    Start-Sleep -Seconds 2
                }
            }
        }
        if (-not $synchronized) {
            throw 'Windows Time did not synchronize.'
        }

        $stage = 'Verification'
        Test-ArtifactSigningTimePolicy -Deployment $Deployment
    }
    catch {
        if ([string]$_.Exception.Message -cmatch
            '^ArtifactSigningTimePolicyFailed:(PeerSet|ToolValidation)$') {
            throw
        }
        throw "ArtifactSigningTimePolicyFailed:$stage"
    }
}

function Test-ArtifactSigningSignTool {
    param([Parameter(Mandatory)] $Deployment)

    $path = $Deployment.Values.SignToolPath
    Assert-ArtifactSigningDirectPath -Path $path -Directory $false
    $programFilesX86 = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::ProgramFilesX86)
    $kitsRoot = Join-Path $programFilesX86 'Windows Kits\10\bin'
    $canonicalPath = [IO.Path]::GetFullPath($path)
    $canonicalKitsRoot = [IO.Path]::GetFullPath(
        $kitsRoot).TrimEnd('\')
    if (-not $canonicalPath.StartsWith(
            "$canonicalKitsRoot\",
            [StringComparison]::OrdinalIgnoreCase) -or
        $canonicalPath.Substring(
            $canonicalKitsRoot.Length + 1) -cnotmatch
                '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\\x64\\signtool\.exe$') {
        throw 'The installed SignTool path is outside the pinned x64 Windows SDK location.'
    }
    $digest = (
        Get-FileHash -LiteralPath $path -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    $versionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo(
        $path)
    $version = '{0}.{1}.{2}.{3}' -f @(
        $versionInfo.FileMajorPart,
        $versionInfo.FileMinorPart,
        $versionInfo.FileBuildPart,
        $versionInfo.FilePrivatePart)
    if ($digest -cne $Deployment.Values.SignToolSha256 -or
        $version -cne $Deployment.Values.SignToolFileVersion) {
        throw 'The installed SignTool does not match deployment policy.'
    }
}

function Test-ArtifactSigningComponentVersions {
    param(
        [Parameter(Mandatory)] $Paths,
        [Parameter(Mandatory)] $Deployment
    )

    foreach ($component in @(
            @{
                Path = Join-Path $Paths.GatewayRoot `
                    'ArtifactSigning.Gateway.exe'
                Version = $Deployment.Values.GatewayVersion
            },
            @{
                Path = Join-Path $Paths.WorkerRoot `
                    'ArtifactSigning.Worker.exe'
                Version = $Deployment.Values.WorkerVersion
            },
            @{
                Path = Join-Path $Paths.InstallerRoot `
                    'artifact-signctl.exe'
                Version = $Deployment.Values.CliVersion
            })) {
        Assert-ArtifactSigningDirectPath `
            -Path $component.Path -Directory $false
        $versionText = [Diagnostics.FileVersionInfo]::GetVersionInfo(
            $component.Path).FileVersion
        $version = $null
        $expected = [Version]::Parse("$($component.Version).0")
        if (-not [Version]::TryParse($versionText, [ref]$version) -or
            $version -ne $expected) {
            throw 'An installed component version does not match deployment policy.'
        }
    }
}

function Write-ArtifactSigningInstalledControlState {
    param(
        [Parameter(Mandatory)] $Paths,
        [Parameter(Mandatory)][string] $PackageRoot,
        [Parameter(Mandatory)][string] $ExpectedInventorySha256,
        [Parameter(Mandatory)] $Deployment
    )

    if (-not (Test-Path -LiteralPath $Paths.ControlRoot)) {
        [IO.Directory]::CreateDirectory($Paths.ControlRoot) | Out-Null
    }
    $builtIn = Get-ArtifactSigningBuiltInSids
    $admins = @($builtIn.System, $builtIn.Administrators)
    Set-ArtifactSigningExactAcl -Path $Paths.ControlRoot `
        -FullControl $admins -ReadAndExecute @() -Directory $true
    $installedLines = @(
        Get-ChildItem -LiteralPath $Paths.InstallRoot `
            -File -Recurse -Force |
            ForEach-Object {
                Assert-ArtifactSigningDirectPath `
                    -Path $_.FullName -Directory $false
                $relative = Get-ArtifactSigningRelativePath `
                    -Root $Paths.InstallRoot -Path $_.FullName
                if ($relative -cnotmatch
                    '^(Gateway|Worker|Installer)/[A-Za-z0-9._/-]+$') {
                    throw 'The installed payload contains an unsupported path.'
                }
                $digest = (
                    Get-FileHash -LiteralPath $_.FullName `
                        -Algorithm SHA256
                ).Hash.ToLowerInvariant()
                "$digest $($_.Length) $relative"
            } |
            Sort-Object
    )
    if ($installedLines.Count -lt 3) {
        throw 'The installed payload inventory is incomplete.'
    }
    [IO.File]::WriteAllText(
        $Paths.InstalledInventory,
        ([string]::Join("`n", $installedLines) + "`n"),
        [Text.Encoding]::ASCII)
    if (Test-Path -LiteralPath $Paths.InstalledDeployment) {
        Assert-ArtifactSigningDirectPath `
            -Path $Paths.InstalledDeployment -Directory $false
        $existingDeployment = Get-Item `
            -LiteralPath $Paths.InstalledDeployment -Force
        if ($existingDeployment.IsReadOnly) {
            $existingDeployment.IsReadOnly = $false
        }
    }
    [IO.File]::Copy(
        (Join-Path $PackageRoot $script:DeploymentName),
        $Paths.InstalledDeployment,
        $true)
    $installedDeployment = Get-Item `
        -LiteralPath $Paths.InstalledDeployment -Force
    if ($installedDeployment.IsReadOnly) {
        $installedDeployment.IsReadOnly = $false
    }
    [IO.File]::WriteAllText(
        $Paths.InstalledReleaseDigest,
        "$ExpectedInventorySha256`n",
        [Text.Encoding]::ASCII)
    $packageProfileSetLock = Join-Path $PackageRoot 'profiles\profile-set.lock'
    Test-ArtifactSigningProfileSetLock `
        -Path $packageProfileSetLock `
        -ExpectedProfileSetSha256 $Deployment.Values.ProfileSetSha256
    if (Test-Path -LiteralPath $Paths.InstalledProfileSetLock) {
        Assert-ArtifactSigningDirectPath `
            -Path $Paths.InstalledProfileSetLock -Directory $false
        $existingProfileSetLock = Get-Item `
            -LiteralPath $Paths.InstalledProfileSetLock -Force
        if ($existingProfileSetLock.IsReadOnly) {
            $existingProfileSetLock.IsReadOnly = $false
        }
    }
    [IO.File]::Copy(
        $packageProfileSetLock,
        $Paths.InstalledProfileSetLock,
        $true)
    $installedProfileSetLock = Get-Item `
        -LiteralPath $Paths.InstalledProfileSetLock -Force
    if ($installedProfileSetLock.IsReadOnly) {
        $installedProfileSetLock.IsReadOnly = $false
    }
    foreach ($file in @(
            $Paths.InstalledInventory,
            $Paths.InstalledDeployment,
            $Paths.InstalledReleaseDigest,
            $Paths.InstalledProfileSetLock)) {
        Set-ArtifactSigningExactAcl -Path $file `
            -FullControl $admins -ReadAndExecute @() `
            -Directory $false
    }
}

function Test-ArtifactSigningInstalledProfileSetEvidence {
    param(
        [Parameter(Mandatory)] $Paths,
        [Parameter(Mandatory)] $Deployment
    )

    Test-ArtifactSigningProfileSetLock `
        -Path $Paths.InstalledProfileSetLock `
        -ExpectedProfileSetSha256 $Deployment.Values.ProfileSetSha256
}

function Test-ArtifactSigningInstalledPayload {
    param([Parameter(Mandatory)] $Paths)

    Assert-ArtifactSigningDirectPath `
        -Path $Paths.InstalledInventory -Directory $false
    $bytes = [IO.File]::ReadAllBytes($Paths.InstalledInventory)
    if ($bytes.Length -lt 1 -or $bytes.Length -gt 1048576 -or
        -not (Test-ArtifactSigningAsciiBytes -Bytes $bytes)) {
        throw 'The installed payload inventory is invalid.'
    }
    $text = [Text.Encoding]::ASCII.GetString($bytes)
    if ($text.Contains("`r") -or -not $text.EndsWith("`n")) {
        throw 'The installed payload inventory is not canonical.'
    }

    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    foreach ($line in $text.Split(
            [char[]]@("`n"),
            [StringSplitOptions]::RemoveEmptyEntries)) {
        if ($line -cnotmatch
            '^([0-9a-f]{64}) ([1-9][0-9]{0,9}) ((?:Gateway|Worker|Installer)/[A-Za-z0-9._/-]+)$') {
            throw 'The installed payload inventory has an invalid entry.'
        }
        $relative = $Matches[3]
        if ($relative.Contains('//') -or
            $relative.Split('/') -contains '..' -or
            -not $seen.Add($relative)) {
            throw 'The installed payload inventory is ambiguous.'
        }
        $path = Join-Path $Paths.InstallRoot (
            $relative.Replace(
                '/',
                [IO.Path]::DirectorySeparatorChar))
        Assert-ArtifactSigningDirectPath -Path $path -Directory $false
        $file = Get-Item -LiteralPath $path -Force
        if ($file.Length -ne [long]$Matches[2] -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).
                Hash.ToLowerInvariant() -cne $Matches[1]) {
            throw 'An installed payload file has drifted.'
        }
    }

    $actual = @(
        Get-ChildItem -LiteralPath $Paths.InstallRoot `
            -File -Recurse -Force |
            ForEach-Object {
                Get-ArtifactSigningRelativePath `
                    -Root $Paths.InstallRoot -Path $_.FullName
            } |
            Sort-Object
    )
    $expected = @($seen | Sort-Object)
    if ([string]::Join("`n", $actual) -cne
        [string]::Join("`n", $expected)) {
        throw 'The installed payload contains unexpected or missing files.'
    }
}

function Test-ArtifactSigningControlAcls {
    param([Parameter(Mandatory)] $Paths)

    $builtIn = Get-ArtifactSigningBuiltInSids
    $admins = @($builtIn.System, $builtIn.Administrators)
    try {
        Test-ArtifactSigningExactAcl -Path $Paths.ControlRoot `
            -FullControl $admins -ReadAndExecute @() -Directory $true
    }
    catch {
        $rootFailureReasons = @{
            'ArtifactSigningExactAclFailed:DirectPath' =
                'ArtifactSigningControlAclFailed:RootDirectPath'
            'ArtifactSigningExactAclFailed:SecurityDescriptor' =
                'ArtifactSigningControlAclFailed:RootSecurityDescriptor'
            'ArtifactSigningExactAclFailed:OwnerOrProtection' =
                'ArtifactSigningControlAclFailed:RootOwnerOrProtection'
            'ArtifactSigningExactAclFailed:Rules' =
                'ArtifactSigningControlAclFailed:RootRules'
        }
        $failureMessage = [string]$_.Exception.Message
        if ($rootFailureReasons.ContainsKey($failureMessage)) {
            throw [string]$rootFailureReasons[$failureMessage]
        }
        throw 'ArtifactSigningControlAclFailed:Root'
    }
    foreach ($controlFile in @(
            @{
                Path = $Paths.InstalledInventory
                Failure = 'ArtifactSigningControlAclFailed:Inventory'
            },
            @{
                Path = $Paths.InstalledDeployment
                Failure = 'ArtifactSigningControlAclFailed:Deployment'
            },
            @{
                Path = $Paths.InstalledReleaseDigest
                Failure = 'ArtifactSigningControlAclFailed:ReleaseDigest'
            },
            @{
                Path = $Paths.InstalledProfileSetLock
                Failure = 'ArtifactSigningControlAclFailed:ProfileSetLock'
            })) {
        try {
            Test-ArtifactSigningExactAcl -Path $controlFile.Path `
                -FullControl $admins -ReadAndExecute @() `
                -Directory $false
        }
        catch {
            throw [string]$controlFile.Failure
        }
    }
}

function Read-ArtifactSigningRollbackState {
    param([Parameter(Mandatory)][string] $RollbackRoot)

    $path = Join-Path $RollbackRoot 'rollback-state.txt'
    Assert-ArtifactSigningDirectPath -Path $path -Directory $false
    $bytes = [IO.File]::ReadAllBytes($path)
    if ($bytes.Length -lt 1 -or $bytes.Length -gt 512 -or
        -not (Test-ArtifactSigningAsciiBytes -Bytes $bytes)) {
        throw 'The rollback transaction state is invalid.'
    }
    $text = [Text.Encoding]::ASCII.GetString($bytes)
    if ($text.Contains("`r") -or -not $text.EndsWith("`n")) {
        throw 'The rollback transaction state is not canonical.'
    }
    $lines = $text.Split(
        [char[]]@("`n"),
        [StringSplitOptions]::None)
    if ($lines.Count -ne 5 -or
        $lines[4] -cne '' -or
        $lines[0] -cne 'Format=ArtifactSigningRollbackStateV1') {
        throw 'The rollback transaction state is invalid.'
    }
    if ($lines[1] -cnotmatch
        '^State=(Prepared|CurrentMoved|PriorMoved|ControlRestored|Verified)$') {
        throw 'The rollback transaction state is invalid.'
    }
    $state = $Matches[1]
    if ($lines[2] -cnotmatch
        '^FailedUpdateName=(ArtifactSigning\.failed-[0-9]{14})$') {
        throw 'The rollback transaction state is invalid.'
    }
    $failedUpdateName = $Matches[1]
    if ($lines[3] -cnotmatch
        '^FailedUpdateDisposition=(Pending|Retained|Absent)$') {
        throw 'The rollback transaction state is invalid.'
    }
    $failedUpdateDisposition = $Matches[1]
    if (($state -ceq 'Prepared' -and
            $failedUpdateDisposition -cne 'Pending') -or
        ($state -cne 'Prepared' -and
            $failedUpdateDisposition -cnotin @('Retained', 'Absent'))) {
        throw 'The rollback transaction state is invalid.'
    }
    $canonical =
        "Format=ArtifactSigningRollbackStateV1`n" +
        "State=$state`n" +
        "FailedUpdateName=$failedUpdateName`n" +
        "FailedUpdateDisposition=$failedUpdateDisposition`n"
    if ($text -cne $canonical) {
        throw 'The rollback transaction state is not canonical.'
    }
    $builtIn = Get-ArtifactSigningBuiltInSids
    Test-ArtifactSigningExactAcl -Path $path `
        -FullControl @($builtIn.System, $builtIn.Administrators) `
        -ReadAndExecute @() -Directory $false
    return [pscustomobject]@{
        State = $state
        FailedUpdateName = $failedUpdateName
        FailedUpdateDisposition = $failedUpdateDisposition
    }
}

function Write-ArtifactSigningRollbackState {
    param(
        [Parameter(Mandatory)][string] $RollbackRoot,
        [Parameter(Mandatory)]
        [ValidateSet(
            'Absent',
            'Prepared',
            'CurrentMoved',
            'PriorMoved',
            'ControlRestored')]
        [string] $ExpectedState,
        [Parameter(Mandatory)]
        [ValidateSet(
            'Prepared',
            'CurrentMoved',
            'PriorMoved',
            'ControlRestored',
            'Verified')]
        [string] $NewState,
        [Parameter(Mandatory)]
        [ValidatePattern('^ArtifactSigning\.failed-[0-9]{14}$')]
        [string] $FailedUpdateName,
        [Parameter(Mandatory)]
        [ValidateSet('None', 'Pending', 'Retained', 'Absent')]
        [string] $ExpectedDisposition,
        [Parameter(Mandatory)]
        [ValidateSet('Pending', 'Retained', 'Absent')]
        [string] $NewDisposition
    )

    $stateTransitionValid =
        ($ExpectedState -ceq 'Absent' -and
            $ExpectedDisposition -ceq 'None' -and
            $NewState -ceq 'Prepared' -and
            $NewDisposition -ceq 'Pending') -or
        ($ExpectedState -ceq 'Prepared' -and
            $ExpectedDisposition -ceq 'Pending' -and
            $NewState -ceq 'CurrentMoved' -and
            $NewDisposition -cin @('Retained', 'Absent')) -or
        ($ExpectedState -ceq 'CurrentMoved' -and
            $ExpectedDisposition -cin @('Retained', 'Absent') -and
            $NewState -ceq 'PriorMoved' -and
            $NewDisposition -ceq $ExpectedDisposition) -or
        ($ExpectedState -ceq 'PriorMoved' -and
            $ExpectedDisposition -cin @('Retained', 'Absent') -and
            $NewState -ceq 'ControlRestored' -and
            $NewDisposition -ceq $ExpectedDisposition) -or
        ($ExpectedState -ceq 'ControlRestored' -and
            $ExpectedDisposition -cin @('Retained', 'Absent') -and
            $NewState -ceq 'Verified' -and
            $NewDisposition -ceq $ExpectedDisposition)
    if (-not $stateTransitionValid) {
        throw 'The rollback transaction transition is invalid.'
    }
    Assert-ArtifactSigningDirectPath `
        -Path $RollbackRoot -Directory $true
    $path = Join-Path $RollbackRoot 'rollback-state.txt'
    if ($ExpectedState -ceq 'Absent') {
        if (Test-Path -LiteralPath $path) {
            throw 'A rollback transaction state already exists.'
        }
    }
    else {
        $current = Read-ArtifactSigningRollbackState `
            -RollbackRoot $RollbackRoot
        if ($current.State -cne $ExpectedState -or
            $current.FailedUpdateName -cne $FailedUpdateName -or
            $current.FailedUpdateDisposition -cne
                $ExpectedDisposition) {
            throw 'The rollback transaction state changed unexpectedly.'
        }
    }

    $builtIn = Get-ArtifactSigningBuiltInSids
    $stateAdministrators = @(
        $builtIn.System,
        $builtIn.Administrators)
    $previous = Join-Path $RollbackRoot 'rollback-state.previous'
    if (Test-Path -LiteralPath $previous) {
        Assert-ArtifactSigningDirectPath `
            -Path $previous -Directory $false
        Test-ArtifactSigningExactAcl -Path $previous `
            -FullControl $stateAdministrators `
            -ReadAndExecute @() -Directory $false
        Remove-Item -LiteralPath $previous -Force
    }
    $next = Join-Path $RollbackRoot 'rollback-state.next'
    if (Test-Path -LiteralPath $next) {
        Assert-ArtifactSigningDirectPath -Path $next -Directory $false
        Remove-Item -LiteralPath $next -Force
    }
    [IO.File]::WriteAllText(
        $next,
        "Format=ArtifactSigningRollbackStateV1`n" +
        "State=$NewState`n" +
        "FailedUpdateName=$FailedUpdateName`n" +
        "FailedUpdateDisposition=$NewDisposition`n",
        [Text.Encoding]::ASCII)
    Set-ArtifactSigningExactAcl -Path $next `
        -FullControl $stateAdministrators `
        -ReadAndExecute @() -Directory $false
    if (Test-Path -LiteralPath $path) {
        [IO.File]::Replace($next, $path, $previous)
    }
    else {
        Move-Item -LiteralPath $next -Destination $path
    }
    Test-ArtifactSigningExactAcl -Path $path `
        -FullControl $stateAdministrators `
        -ReadAndExecute @() -Directory $false
    if (Test-Path -LiteralPath $previous) {
        Assert-ArtifactSigningDirectPath `
            -Path $previous -Directory $false
        Test-ArtifactSigningExactAcl -Path $previous `
            -FullControl $stateAdministrators `
            -ReadAndExecute @() -Directory $false
        Remove-Item -LiteralPath $previous -Force
    }
}

function Test-ArtifactSigningFailedUpdateDisposition {
    param(
        [Parameter(Mandatory)] $Transaction,
        [Parameter(Mandatory)][string] $FailedUpdatePath
    )

    if ((Split-Path -Leaf $FailedUpdatePath) -cne
        $Transaction.FailedUpdateName) {
        throw 'The failed-update generation path is invalid.'
    }
    $exists = Test-Path -LiteralPath $FailedUpdatePath
    if ($Transaction.FailedUpdateDisposition -ceq 'Retained') {
        if (-not $exists) {
            throw 'The retained failed-update generation is missing.'
        }
        Assert-ArtifactSigningDirectPath `
            -Path $FailedUpdatePath -Directory $true
    }
    elseif ($Transaction.FailedUpdateDisposition -ceq 'Absent') {
        if ($exists) {
            throw 'An unexpected failed-update generation is present.'
        }
    }
}

function Move-ArtifactSigningRollbackCurrentGeneration {
    param(
        [Parameter(Mandatory)] $Paths,
        [Parameter(Mandatory)][string] $FailedUpdatePath,
        [Parameter(Mandatory)] $Transaction
    )

    if ($Transaction.State -cne 'Prepared' -or
        $Transaction.FailedUpdateDisposition -cne 'Pending' -or
        (Split-Path -Leaf $FailedUpdatePath) -cne
            $Transaction.FailedUpdateName) {
        throw 'The rollback current-generation state is invalid.'
    }
    $liveExists = Test-Path -LiteralPath $Paths.InstallRoot
    $failedExists = Test-Path -LiteralPath $FailedUpdatePath
    if ($liveExists -and -not $failedExists) {
        Assert-ArtifactSigningDirectPath `
            -Path $Paths.InstallRoot -Directory $true
        Move-Item -LiteralPath $Paths.InstallRoot `
            -Destination $FailedUpdatePath
        $newDisposition = 'Retained'
    }
    elseif (-not $liveExists -and $failedExists) {
        Assert-ArtifactSigningDirectPath `
            -Path $FailedUpdatePath -Directory $true
        $newDisposition = 'Retained'
    }
    elseif (-not $liveExists -and -not $failedExists) {
        $newDisposition = 'Absent'
    }
    else {
        throw 'The rollback current-generation move is ambiguous.'
    }
    Write-ArtifactSigningRollbackState `
        -RollbackRoot $Paths.RollbackRoot `
        -ExpectedState Prepared -NewState CurrentMoved `
        -FailedUpdateName $Transaction.FailedUpdateName `
        -ExpectedDisposition Pending `
        -NewDisposition $newDisposition
    $updated = Read-ArtifactSigningRollbackState `
        -RollbackRoot $Paths.RollbackRoot
    Test-ArtifactSigningFailedUpdateDisposition `
        -Transaction $updated -FailedUpdatePath $FailedUpdatePath
    return $updated
}

function Move-ArtifactSigningRollbackPriorGeneration {
    param(
        [Parameter(Mandatory)] $Paths,
        [Parameter(Mandatory)][string] $RollbackInstallation,
        [Parameter(Mandatory)][string] $FailedUpdatePath,
        [Parameter(Mandatory)] $Transaction
    )

    if ($Transaction.State -cne 'CurrentMoved' -or
        $Transaction.FailedUpdateDisposition -cnotin @(
            'Retained',
            'Absent')) {
        throw 'The rollback prior-generation state is invalid.'
    }
    Test-ArtifactSigningFailedUpdateDisposition `
        -Transaction $Transaction -FailedUpdatePath $FailedUpdatePath
    $liveExists = Test-Path -LiteralPath $Paths.InstallRoot
    $priorExists = Test-Path -LiteralPath $RollbackInstallation
    if (-not $liveExists -and $priorExists) {
        Assert-ArtifactSigningDirectPath `
            -Path $RollbackInstallation -Directory $true
        Move-Item -LiteralPath $RollbackInstallation `
            -Destination $Paths.InstallRoot
    }
    elseif (-not $liveExists -or $priorExists) {
        throw 'The rollback prior-generation move is ambiguous.'
    }
    Write-ArtifactSigningRollbackState `
        -RollbackRoot $Paths.RollbackRoot `
        -ExpectedState CurrentMoved -NewState PriorMoved `
        -FailedUpdateName $Transaction.FailedUpdateName `
        -ExpectedDisposition $Transaction.FailedUpdateDisposition `
        -NewDisposition $Transaction.FailedUpdateDisposition
    return Read-ArtifactSigningRollbackState `
        -RollbackRoot $Paths.RollbackRoot
}

function Remove-ArtifactSigningDirectTree {
    param([Parameter(Mandatory)][string] $Path)

    Assert-ArtifactSigningDirectPath -Path $Path -Directory $true
    foreach ($item in Get-ChildItem -LiteralPath $Path `
        -Recurse -Force) {
        $null = Get-ArtifactSigningRelativePath `
            -Root $Path -Path $item.FullName
        Assert-ArtifactSigningDirectPath `
            -Path $item.FullName -Directory $item.PSIsContainer
    }
    Remove-Item -LiteralPath $Path -Recurse -Force
}

function Start-ArtifactSigningServices {
    foreach ($name in @(
            $script:WorkerServiceName,
            $script:GatewayServiceName)) {
        $service = Get-Service -Name $name -ErrorAction Stop
        if ($service.Status -ne 'Running') {
            Start-Service -Name $name
            $service.WaitForStatus(
                'Running',
                [TimeSpan]::FromSeconds(30))
        }
    }
}

function Write-ArtifactSigningInstallerEvent {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string] $EntryType,
        [Parameter(Mandatory)][int] $EventId,
        [Parameter(Mandatory)]
        [ValidateSet(
            'INSTALL_OK',
            'INSTALL_FAILED',
            'VERIFY_OK',
            'VERIFY_FAILED',
            'UNINSTALL_OK',
            'ROLLBACK_OK')]
        [string] $ResultCode
    )

    try {
        Write-EventLog -LogName Application `
            -Source ArtifactSigningInstaller `
            -EntryType $EntryType `
            -EventId $EventId `
            -Message $ResultCode
    }
    catch {
        if ($ResultCode -ceq 'INSTALL_OK') {
            throw 'The installer audit event could not be written.'
        }
    }
}
