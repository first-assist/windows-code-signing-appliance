Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..\..'))
$installerRoot = Join-Path $repositoryRoot 'installer'

function Assert-True {
    param(
        [Parameter(Mandatory)][bool] $Condition,
        [Parameter(Mandatory)][string] $Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Assert-Throws {
    param(
        [Parameter(Mandatory)][scriptblock] $Action,
        [Parameter(Mandatory)][string] $Message
    )

    try {
        & $Action
    }
    catch {
        return
    }
    throw $Message
}

$parseErrors = @()
Get-ChildItem -LiteralPath $installerRoot -Filter '*.ps1' -File |
    ForEach-Object {
        [Management.Automation.Language.Parser]::ParseFile(
            $_.FullName,
            [ref]$null,
            [ref]$parseErrors) | Out-Null
    }
Assert-True -Condition ($parseErrors.Count -eq 0) `
    -Message 'An installer script has a PowerShell parse error.'

[xml] $directoryBuild = [IO.File]::ReadAllText(
    (Join-Path $repositoryRoot 'Directory.Build.props'))
Assert-True `
    -Condition (
        $directoryBuild.Project.PropertyGroup.IncludeSourceRevisionInInformationalVersion `
            -ceq 'false') `
    -Message 'Builds must keep source revisions in sealed release evidence, not executable versions.'

. (Join-Path $installerRoot 'ArtifactSigning.Installer.ps1')

Assert-True `
    -Condition (Test-ArtifactSigningAsciiBytes `
        -Bytes ([byte[]]@(0, 10, 32, 126, 127))) `
    -Message 'Canonical ASCII bytes were rejected.'
Assert-True `
    -Condition (-not (Test-ArtifactSigningAsciiBytes `
        -Bytes ([byte[]]@(65, 128)))) `
    -Message 'A non-ASCII byte was accepted.'

$firewallTestPaths = [pscustomobject]@{
    GatewayRoot = [IO.Path]::GetFullPath('/test/Gateway')
    WorkerRoot = [IO.Path]::GetFullPath('/test/Worker')
}
$firewallTestDeployment = [pscustomobject]@{
    IsMicrosoftArtifactSigning = $false
    Values = @{
        SignToolPath = [IO.Path]::GetFullPath(
            '/test/WindowsKits/x64/signtool.exe')
    }
    GatewayListenAddress = '10.20.30.40'
    GatewayListenPort = 8443
    GatewayIngressRemoteAddresses = @('10.20.30.10', '10.20.30.11')
    TimestampRelayAddress = '10.20.30.50'
    TimestampRelayPort = 8080
    CertificateStatusRemoteAddresses = @()
    TimeServerAddresses = @('10.20.30.1')
    DnsServerAddresses = @()
}
$script:firewallTestRules = @(
    [pscustomobject]@{
        Name = 'ArtifactSigning-Gateway-In'
        Enabled = 'True'
        Action = 'Allow'
        Profile = 'Any'
        Direction = 'Inbound'
    },
    [pscustomobject]@{
        Name = 'ArtifactSigning-Worker-Timestamp-Out'
        Enabled = 'True'
        Action = 'Allow'
        Profile = 'Any'
        Direction = 'Outbound'
    },
    [pscustomobject]@{
        Name = 'ArtifactSigning-Worker-Readiness-Out'
        Enabled = 'True'
        Action = 'Allow'
        Profile = 'Any'
        Direction = 'Outbound'
    },
    [pscustomobject]@{
        Name = 'ArtifactSigning-Time-Out'
        Enabled = 'True'
        Action = 'Allow'
        Profile = 'Any'
        Direction = 'Outbound'
    }
)
$script:firewallTestInvalidTarget = ''
try {
    function Get-NetFirewallProfile {
        [CmdletBinding()]
        param()

        foreach ($name in @('Domain', 'Private', 'Public')) {
            [pscustomobject]@{
                Name = $name
                DefaultInboundAction = 'Block'
                DefaultOutboundAction = 'Block'
                NotifyOnListen = 'False'
                AllowInboundRules = 'True'
            }
        }
    }
    function Get-NetFirewallRule {
        [CmdletBinding()]
        param(
            [string] $Group,
            [string] $Name
        )

        if ($Group -ceq 'Artifact Signing Appliance') {
            return @($script:firewallTestRules)
        }
        return @($script:firewallTestRules | Where-Object Name -CEQ $Name)
    }
    function Get-NetFirewallPortFilter {
        [CmdletBinding()]
        param([Parameter(ValueFromPipeline)] $InputObject)

        process {
            switch ($InputObject.Name) {
                'ArtifactSigning-Gateway-In' {
                    [pscustomobject]@{
                        Protocol = 'TCP'
                        LocalPort = @('8443')
                        RemotePort = @('Any')
                    }
                }
                'ArtifactSigning-Worker-Timestamp-Out' {
                    [pscustomobject]@{
                        Protocol = 'TCP'
                        LocalPort = @('Any')
                        RemotePort = if (
                            $script:firewallTestInvalidTarget -ceq
                                'WorkerTimestamp') {
                            @('9999')
                        }
                        else {
                            @('8080')
                        }
                    }
                }
                'ArtifactSigning-Worker-Readiness-Out' {
                    [pscustomobject]@{
                        Protocol = 'TCP'
                        LocalPort = @('Any')
                        RemotePort = if (
                            $script:firewallTestInvalidTarget -ceq
                                'WorkerReadiness') {
                            @('9999')
                        }
                        else {
                            @('8080')
                        }
                    }
                }
                'ArtifactSigning-Time-Out' {
                    [pscustomobject]@{
                        Protocol = 'UDP'
                        LocalPort = @('Any')
                        RemotePort = @('123')
                    }
                }
            }
        }
    }
    function Get-NetFirewallAddressFilter {
        [CmdletBinding()]
        param([Parameter(ValueFromPipeline)] $InputObject)

        process {
            switch ($InputObject.Name) {
                'ArtifactSigning-Gateway-In' {
                    [pscustomobject]@{
                        LocalAddress = @('10.20.30.40')
                        RemoteAddress = @('10.20.30.10', '10.20.30.11')
                    }
                }
                'ArtifactSigning-Worker-Timestamp-Out' {
                    [pscustomobject]@{
                        LocalAddress = @('Any')
                        RemoteAddress = @('10.20.30.50')
                    }
                }
                'ArtifactSigning-Worker-Readiness-Out' {
                    [pscustomobject]@{
                        LocalAddress = @('Any')
                        RemoteAddress = @('10.20.30.50')
                    }
                }
                'ArtifactSigning-Time-Out' {
                    [pscustomobject]@{
                        LocalAddress = @('Any')
                        RemoteAddress = @('10.20.30.1')
                    }
                }
            }
        }
    }
    function Get-NetFirewallApplicationFilter {
        [CmdletBinding()]
        param([Parameter(ValueFromPipeline)] $InputObject)

        process {
            $program = switch ($InputObject.Name) {
                'ArtifactSigning-Gateway-In' {
                    Join-Path $firewallTestPaths.GatewayRoot `
                        'ArtifactSigning.Gateway.exe'
                }
                'ArtifactSigning-Worker-Timestamp-Out' {
                    $firewallTestDeployment.Values.SignToolPath
                }
                'ArtifactSigning-Worker-Readiness-Out' {
                    Join-Path $firewallTestPaths.WorkerRoot `
                        'ArtifactSigning.Worker.exe'
                }
                'ArtifactSigning-Time-Out' { 'Any' }
            }
            [pscustomobject]@{ Program = $program }
        }
    }
    function Get-NetFirewallServiceFilter {
        [CmdletBinding()]
        param([Parameter(ValueFromPipeline)] $InputObject)

        process {
            $service = switch ($InputObject.Name) {
                'ArtifactSigning-Gateway-In' {
                    'ArtifactSigningGateway'
                }
                'ArtifactSigning-Worker-Timestamp-Out' {
                    'Any'
                }
                'ArtifactSigning-Worker-Readiness-Out' {
                    'ArtifactSigningWorker'
                }
                'ArtifactSigning-Time-Out' { 'W32Time' }
            }
            [pscustomobject]@{ Service = $service }
        }
    }

    Test-ArtifactSigningFirewallPolicy `
        -Paths $firewallTestPaths -Deployment $firewallTestDeployment

    $script:firewallTestRules[0].Action = 'Block'
    $ruleSetFailure = $null
    try {
        Test-ArtifactSigningFirewallPolicy `
            -Paths $firewallTestPaths -Deployment $firewallTestDeployment
    }
    catch {
        $ruleSetFailure = [string]$_.Exception.Message
    }
    Assert-True `
        -Condition (
            $ruleSetFailure -ceq
                'ArtifactSigningFirewallPolicyFailed:RuleSet') `
        -Message 'An invalid firewall rule set was not classified safely.'
    $script:firewallTestRules[0].Action = 'Allow'

    $script:firewallTestInvalidTarget = 'WorkerTimestamp'
    $targetFailure = $null
    try {
        Test-ArtifactSigningFirewallPolicy `
            -Paths $firewallTestPaths -Deployment $firewallTestDeployment
    }
    catch {
        $targetFailure = [string]$_.Exception.Message
    }
    Assert-True `
        -Condition (
            $targetFailure -ceq
                'ArtifactSigningFirewallPolicyFailed:WorkerTimestamp') `
        -Message 'An invalid firewall filter was not classified safely.'

    $script:firewallTestInvalidTarget = 'WorkerReadiness'
    $targetFailure = $null
    try {
        Test-ArtifactSigningFirewallPolicy `
            -Paths $firewallTestPaths -Deployment $firewallTestDeployment
    }
    catch {
        $targetFailure = [string]$_.Exception.Message
    }
    Assert-True `
        -Condition (
            $targetFailure -ceq
                'ArtifactSigningFirewallPolicyFailed:WorkerReadiness') `
        -Message 'An invalid readiness rule was not classified safely.'
}
finally {
    foreach ($name in @(
            'Get-NetFirewallProfile',
            'Get-NetFirewallRule',
            'Get-NetFirewallPortFilter',
            'Get-NetFirewallAddressFilter',
            'Get-NetFirewallApplicationFilter',
            'Get-NetFirewallServiceFilter')) {
        Remove-Item "Function:\$name" -Force -ErrorAction SilentlyContinue
    }
    Remove-Variable firewallTestRules -Scope Script `
        -Force -ErrorAction SilentlyContinue
    Remove-Variable firewallTestInvalidTarget -Scope Script `
        -Force -ErrorAction SilentlyContinue
}

$script:dynamicKeywordTestInvalidId = ''
try {
    function Get-NetFirewallDynamicKeywordAddress {
        [CmdletBinding()]
        param([Parameter(Mandatory)][string] $Id)

        $definition = @(
            $script:MicrosoftCertificateStatusDynamicKeywords |
                Where-Object Id -CEQ $Id)
        if ($definition.Count -ne 1) {
            return
        }
        [pscustomobject]@{
            Id = $definition[0].Id
            Keyword = if ($Id -ceq $script:dynamicKeywordTestInvalidId) {
                'invalid.example'
            }
            else {
                $definition[0].Fqdn
            }
            AutoResolve = 'True'
        }
    }

    Test-ArtifactSigningMicrosoftCertificateStatusDynamicKeywords
    $script:dynamicKeywordTestInvalidId =
        $script:MicrosoftCertificateStatusDynamicKeywords[0].Id
    $dynamicKeywordFailure = $null
    try {
        Test-ArtifactSigningMicrosoftCertificateStatusDynamicKeywords
    }
    catch {
        $dynamicKeywordFailure = [string]$_.Exception.Message
    }
    Assert-True `
        -Condition ($dynamicKeywordFailure -ceq (
            'ArtifactSigningFirewallPolicyFailed:' +
            'WorkerMicrosoftCertificateStatusKeywords')) `
        -Message 'A drifted Microsoft certificate-status FQDN was accepted.'
}
finally {
    Remove-Item Function:\Get-NetFirewallDynamicKeywordAddress `
        -Force -ErrorAction SilentlyContinue
    Remove-Variable dynamicKeywordTestInvalidId -Scope Script `
        -Force -ErrorAction SilentlyContinue
}

$manualTimePeers = Get-ArtifactSigningManualTimePeers `
    -Deployment $firewallTestDeployment
Assert-True `
    -Condition ($manualTimePeers -ceq '10.20.30.1,0x8') `
    -Message 'The fixed manual Windows Time peer list is not canonical.'
Assert-Throws -Action {
    Get-ArtifactSigningManualTimePeers -Deployment ([pscustomobject]@{
        TimeServerAddresses = @()
    }) | Out-Null
} -Message 'An empty Windows Time peer set was accepted.'

$nativeArgumentCases = @(
    @('create', 'create'),
    @('binPath=', 'binPath='),
    @('', '""'),
    @('C:\Program Files\Tool.exe', '"C:\Program Files\Tool.exe"'),
    @('"C:\Program Files\Tool.exe"', '"\"C:\Program Files\Tool.exe\""'),
    @('a"b', '"a\"b"'),
    @('C:\Path With Space\', '"C:\Path With Space\\"')
)
foreach ($nativeArgumentCase in $nativeArgumentCases) {
    Assert-True `
        -Condition (
            (ConvertTo-ArtifactSigningWindowsCommandLineArgument `
                -Value $nativeArgumentCase[0]) -ceq
                    $nativeArgumentCase[1]) `
        -Message 'A Windows native argument was not encoded canonically.'
}

if ([IO.Path]::DirectorySeparatorChar -eq '\') {
    $serviceControlPath = Get-ArtifactSigningServiceControlPath
    $expectedServiceControlPath = [IO.Path]::GetFullPath(
        (Join-Path ([Environment]::GetFolderPath(
            [Environment+SpecialFolder]::Windows)) 'System32\sc.exe'))
    Assert-True `
        -Condition $serviceControlPath.Equals(
            $expectedServiceControlPath,
            [StringComparison]::OrdinalIgnoreCase) `
        -Message 'The fixed serviced System32 tool was not accepted exactly.'

    $eventSourceTestPath =
        'Software\ArtifactSigningEventSourceTest\' +
        [Guid]::NewGuid().ToString('N')
    $eventSourceTestKey =
        [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey(
            $eventSourceTestPath,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)
    if ($null -eq $eventSourceTestKey) {
        throw 'The Event Log source registry test key could not be created.'
    }
    try {
        $eventSourceTestKey.SetValue(
            'EventMessageFile',
            '%SystemRoot%\System32\EventCreate.exe',
            [Microsoft.Win32.RegistryValueKind]::ExpandString)
        $eventSourceTestKey.SetValue(
            'TypesSupported',
            7,
            [Microsoft.Win32.RegistryValueKind]::DWord)
        Test-ArtifactSigningEventSourceRegistryKey `
            -Key $eventSourceTestKey
        Assert-True `
            -Condition (
                [string]$eventSourceTestKey.GetValue(
                    'EventMessageFile',
                    $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                ) -ceq '%SystemRoot%\System32\EventCreate.exe') `
            -Message 'The Event Log message path was expanded during verification.'

        $eventSourceTestKey.SetValue(
            'Unexpected',
            1,
            [Microsoft.Win32.RegistryValueKind]::DWord)
        Assert-Throws -Action {
            Test-ArtifactSigningEventSourceRegistryKey `
                -Key $eventSourceTestKey
        } -Message 'An unexpected Event Log source value was accepted.'
        $eventSourceTestKey.DeleteValue('Unexpected')

        $eventSourceTestKey.SetValue(
            'TypesSupported',
            '7',
            [Microsoft.Win32.RegistryValueKind]::String)
        Assert-Throws -Action {
            Test-ArtifactSigningEventSourceRegistryKey `
                -Key $eventSourceTestKey
        } -Message 'An incorrect Event Log source value type was accepted.'
    }
    finally {
        $eventSourceTestKey.Dispose()
        [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree(
            $eventSourceTestPath,
            $false)
    }

    $aclReadTestRoot = Join-Path (
        [IO.Path]::GetTempPath()
    ) "artifact-signing-acl-read-test-$([Guid]::NewGuid().ToString('N'))"
    [IO.Directory]::CreateDirectory($aclReadTestRoot) | Out-Null
    $descriptorFailure = $null
    try {
        function Get-Acl {
            [CmdletBinding()]
            param(
                [string] $LiteralPath,
                [switch] $Audit
            )
            $null = $LiteralPath
            $null = $Audit
            throw 'sensitive native descriptor diagnostic'
        }
        Test-ArtifactSigningControlAcls -Paths ([pscustomobject]@{
            ControlRoot = $aclReadTestRoot
            InstalledInventory = (Join-Path $aclReadTestRoot 'inventory.txt')
            InstalledDeployment = (Join-Path $aclReadTestRoot 'deployment.txt')
            InstalledReleaseDigest = (Join-Path $aclReadTestRoot 'release.txt')
        })
    }
    catch {
        $descriptorFailure = [string]$_.Exception.Message
    }
    finally {
        Remove-Item Function:\Get-Acl -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $aclReadTestRoot -Recurse -Force
    }
    Assert-True `
        -Condition (
            $descriptorFailure -ceq
                'ArtifactSigningControlAclFailed:RootSecurityDescriptor') `
        -Message 'A root descriptor-read failure was not safely classified.'

    function New-TestAclRule {
        param(
            [Parameter(Mandatory)]
            [Security.Principal.SecurityIdentifier] $Sid,
            [Security.AccessControl.FileSystemRights] $Rights =
                [Security.AccessControl.FileSystemRights]::FullControl,
            [bool] $Inherited = $false,
            [Security.AccessControl.AccessControlType] $AccessType =
                [Security.AccessControl.AccessControlType]::Allow,
            [Security.AccessControl.InheritanceFlags] $Inheritance =
                [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
            [Security.AccessControl.PropagationFlags] $Propagation =
                [Security.AccessControl.PropagationFlags]::None
        )

        [pscustomobject]@{
            IdentityReference = [pscustomobject]@{ Value = $Sid.Value }
            FileSystemRights = $Rights
            IsInherited = $Inherited
            AccessControlType = $AccessType
            InheritanceFlags = $Inheritance
            PropagationFlags = $Propagation
        }
    }

    function New-TestAclDescriptor {
        param(
            [Parameter(Mandatory)][object[]] $Rules,
            [Parameter(Mandatory)]
            [Security.Principal.SecurityIdentifier] $Owner
        )

        $descriptor = [pscustomobject]@{
            AreAccessRulesProtected = $true
            Owner = $Owner
            Rules = @($Rules)
        }
        $descriptor | Add-Member -MemberType ScriptMethod `
            -Name GetOwner -Value {
                param([type] $TargetType)
                $null = $TargetType
                return $this.Owner
            }
        $descriptor | Add-Member -MemberType ScriptMethod `
            -Name GetAccessRules -Value {
                param(
                    [bool] $IncludeExplicit,
                    [bool] $IncludeInherited,
                    [type] $TargetType
                )
                $null = $IncludeExplicit
                $null = $IncludeInherited
                $null = $TargetType
                return $this.Rules
            }
        return $descriptor
    }

    $aclRuleTestRoot = Join-Path (
        [IO.Path]::GetTempPath()
    ) "artifact-signing-acl-rule-test-$([Guid]::NewGuid().ToString('N'))"
    [IO.Directory]::CreateDirectory($aclRuleTestRoot) | Out-Null
    $aclRuleTestFile = Join-Path $aclRuleTestRoot 'control.txt'
    [IO.File]::WriteAllText($aclRuleTestFile, 'control')
    $executionTrustInstallerRoot = Join-Path $aclRuleTestRoot 'Installer'
    [IO.Directory]::CreateDirectory($executionTrustInstallerRoot) | Out-Null
    $executionTrustVerifier = Join-Path $executionTrustInstallerRoot `
        'verify-artifact-signing-service.ps1'
    $executionTrustCommon = Join-Path $executionTrustInstallerRoot `
        'ArtifactSigning.Installer.ps1'
    [IO.File]::WriteAllText($executionTrustVerifier, 'verifier')
    [IO.File]::WriteAllText($executionTrustCommon, 'common')
    $executionTrustPaths = [pscustomobject]@{
        InstallRoot = $aclRuleTestRoot
        InstallerRoot = $executionTrustInstallerRoot
        GatewayRoot = 'This path must not be inspected by the update trust gate.'
        WorkerRoot = 'This path must not be inspected by the update trust gate.'
    }
    $builtIn = Get-ArtifactSigningBuiltInSids
    $admins = @($builtIn.System, $builtIn.Administrators)
    $readSid = [Security.Principal.SecurityIdentifier]::new(
        [Security.Principal.WellKnownSidType]::WorldSid,
        $null)
    $persistedReadAndExecute =
        [Security.AccessControl.FileSystemRights](
            [int][Security.AccessControl.FileSystemRights]::ReadAndExecute `
            -bor
            [int][Security.AccessControl.FileSystemRights]::Synchronize)
    try {
        Set-ArtifactSigningExactAcl -Path $aclRuleTestRoot `
            -FullControl $admins -ReadAndExecute @($readSid) `
            -Directory $true
        Test-ArtifactSigningExactAcl -Path $aclRuleTestRoot `
            -FullControl $admins -ReadAndExecute @($readSid) `
            -Directory $true
        Set-ArtifactSigningExactAcl -Path $aclRuleTestFile `
            -FullControl $admins -ReadAndExecute @($readSid) `
            -Directory $false
        Test-ArtifactSigningExactAcl -Path $aclRuleTestFile `
            -FullControl $admins -ReadAndExecute @($readSid) `
            -Directory $false

        function Get-Acl {
            [CmdletBinding()]
            param(
                [string] $LiteralPath,
                [switch] $Audit
            )
            $null = $LiteralPath
            $null = $Audit
            if ($null -ne (Get-Variable `
                    -Name aclTestDescriptorsByPath `
                    -Scope Script -ErrorAction SilentlyContinue) -and
                $script:aclTestDescriptorsByPath.ContainsKey(
                    $LiteralPath)) {
                return $script:aclTestDescriptorsByPath[$LiteralPath]
            }
            return $script:aclTestDescriptor
        }

        $validRules = @(
            (New-TestAclRule -Sid $builtIn.System),
            (New-TestAclRule -Sid $builtIn.Administrators),
            (New-TestAclRule -Sid $readSid `
                -Rights $persistedReadAndExecute)
        )
        $script:aclTestDescriptor = New-TestAclDescriptor `
            -Rules $validRules -Owner $builtIn.System
        Test-ArtifactSigningExactAcl -Path $aclRuleTestRoot `
            -FullControl $admins -ReadAndExecute @($readSid) `
            -Directory $true
        Test-ArtifactSigningInstalledVerifierExecutionTrust `
            -Paths $executionTrustPaths

        foreach ($unsafeTarget in @(
                @($aclRuleTestRoot, 'InstallRoot'),
                @($executionTrustInstallerRoot, 'InstallerRoot'),
                @($executionTrustVerifier, 'Verifier'),
                @($executionTrustCommon, 'Common'))) {
            foreach ($unsafeRight in @(
                    [Security.AccessControl.FileSystemRights]::WriteData,
                    [Security.AccessControl.FileSystemRights]::AppendData,
                    [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes,
                    [Security.AccessControl.FileSystemRights]::WriteAttributes,
                    [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles,
                    [Security.AccessControl.FileSystemRights]::Delete,
                    [Security.AccessControl.FileSystemRights]::ChangePermissions,
                    [Security.AccessControl.FileSystemRights]::TakeOwnership)) {
                $unsafeExecutionTrustDescriptor = New-TestAclDescriptor `
                    -Rules @(
                        (New-TestAclRule -Sid $builtIn.System),
                        (New-TestAclRule -Sid $builtIn.Administrators),
                        (New-TestAclRule -Sid $readSid -Rights $unsafeRight)
                    ) -Owner $builtIn.System
                $script:aclTestDescriptorsByPath = @{
                    $unsafeTarget[0] = $unsafeExecutionTrustDescriptor
                }
                $executionTrustFailure = $null
                try {
                    Test-ArtifactSigningInstalledVerifierExecutionTrust `
                        -Paths $executionTrustPaths
                }
                catch {
                    $executionTrustFailure = [string]$_.Exception.Message
                }
                Assert-True `
                    -Condition (
                        $executionTrustFailure -ceq
                            "ArtifactSigningUpdateExecutionTrustFailed:$($unsafeTarget[1])") `
                    -Message 'An unsafe update execution-path right was accepted.'
            }
        }
        Remove-Variable aclTestDescriptorsByPath -Scope Script `
            -Force -ErrorAction SilentlyContinue

        $invalidExecutionTrustRules = @(
            @(
                (New-TestAclRule -Sid $builtIn.System -Inherited $true),
                (New-TestAclRule -Sid $builtIn.Administrators)
            ),
            @(
                (New-TestAclRule -Sid $builtIn.System `
                    -Rights $persistedReadAndExecute),
                (New-TestAclRule -Sid $builtIn.Administrators)
            ),
            @(
                (New-TestAclRule -Sid $builtIn.System),
                (New-TestAclRule -Sid $builtIn.Administrators),
                (New-TestAclRule -Sid $readSid `
                    -AccessType ([Security.AccessControl.AccessControlType]::Deny))
            )
        )
        foreach ($invalidExecutionTrustRuleset in
                 $invalidExecutionTrustRules) {
            $script:aclTestDescriptor = New-TestAclDescriptor `
                -Rules $invalidExecutionTrustRuleset -Owner $builtIn.System
            $executionTrustFailure = $null
            try {
                Test-ArtifactSigningInstalledVerifierExecutionTrust `
                    -Paths $executionTrustPaths
            }
            catch {
                $executionTrustFailure = [string]$_.Exception.Message
            }
            Assert-True `
                -Condition (
                    $executionTrustFailure -ceq
                        'ArtifactSigningUpdateExecutionTrustFailed:InstallRoot') `
                -Message 'An invalid update execution-path ACL was accepted.'
        }

        $script:aclTestDescriptor = New-TestAclDescriptor `
            -Rules $validRules -Owner $builtIn.Administrators
        $executionTrustOwnerFailure = $null
        try {
            Test-ArtifactSigningInstalledVerifierExecutionTrust `
                -Paths $executionTrustPaths
        }
        catch {
            $executionTrustOwnerFailure = [string]$_.Exception.Message
        }
        Assert-True `
            -Condition (
                $executionTrustOwnerFailure -ceq
                    'ArtifactSigningUpdateExecutionTrustFailed:InstallRoot') `
            -Message 'A non-SYSTEM update execution-path owner was accepted.'

        $script:aclTestDescriptor = New-TestAclDescriptor `
            -Rules $validRules -Owner $builtIn.System

        $controlStatePackageRoot = Join-Path $aclRuleTestRoot `
            'control-state-package'
        $controlStateInstallRoot = Join-Path $aclRuleTestRoot `
            'control-state-install'
        $controlStateRoot = Join-Path $aclRuleTestRoot `
            'control-state-root'
        foreach ($directory in @(
                $controlStatePackageRoot,
                $controlStateInstallRoot,
                $controlStateRoot,
                (Join-Path $controlStateInstallRoot 'Gateway'),
                (Join-Path $controlStateInstallRoot 'Worker'),
                (Join-Path $controlStateInstallRoot 'Installer'))) {
            [IO.Directory]::CreateDirectory($directory) | Out-Null
        }
        $controlStateSourceDeployment = Join-Path `
            $controlStatePackageRoot 'deployment.txt'
        [IO.File]::WriteAllText(
            $controlStateSourceDeployment,
            'replacement-deployment')
        (Get-Item -LiteralPath $controlStateSourceDeployment -Force).
            IsReadOnly = $true
        foreach ($componentFile in @(
                (Join-Path $controlStateInstallRoot 'Gateway/gateway.exe'),
                (Join-Path $controlStateInstallRoot 'Worker/worker.exe'),
                (Join-Path $controlStateInstallRoot 'Installer/installer.ps1'))) {
            [IO.File]::WriteAllText($componentFile, 'payload')
        }
        $controlStatePaths = [pscustomobject]@{
            InstallRoot = $controlStateInstallRoot
            ControlRoot = $controlStateRoot
            InstalledInventory = Join-Path $controlStateRoot `
                'installed-inventory.txt'
            InstalledDeployment = Join-Path $controlStateRoot `
                'installed-deployment.txt'
            InstalledReleaseDigest = Join-Path $controlStateRoot `
                'installed-release.sha256'
        }
        [IO.File]::WriteAllText(
            $controlStatePaths.InstalledDeployment,
            'prior-deployment')
        (Get-Item `
            -LiteralPath $controlStatePaths.InstalledDeployment -Force).
            IsReadOnly = $true
        Write-ArtifactSigningInstalledControlState `
            -Paths $controlStatePaths `
            -PackageRoot $controlStatePackageRoot `
            -ExpectedInventorySha256 ('1' * 64)
        Assert-True `
            -Condition (
                [IO.File]::ReadAllText(
                    $controlStatePaths.InstalledDeployment) -ceq
                    'replacement-deployment' -and
                -not (Get-Item -LiteralPath `
                    $controlStatePaths.InstalledDeployment -Force).
                    IsReadOnly) `
            -Message 'A read-only deployment control file was not replaced safely.'

        $rollbackStateRoot = Join-Path $aclRuleTestRoot `
            'rollback-state-root'
        [IO.Directory]::CreateDirectory($rollbackStateRoot) | Out-Null
        $failedUpdateName = 'ArtifactSigning.failed-20260803040506'
        $rollbackTransitions = @(
            @('Absent', 'None', 'Prepared', 'Pending'),
            @('Prepared', 'Pending', 'CurrentMoved', 'Retained'),
            @('CurrentMoved', 'Retained', 'PriorMoved', 'Retained'),
            @('PriorMoved', 'Retained', 'ControlRestored', 'Retained'),
            @('ControlRestored', 'Retained', 'Verified', 'Retained'))
        foreach ($transition in $rollbackTransitions) {
            Write-ArtifactSigningRollbackState `
                -RollbackRoot $rollbackStateRoot `
                -ExpectedState $transition[0] `
                -ExpectedDisposition $transition[1] `
                -NewState $transition[2] `
                -NewDisposition $transition[3] `
                -FailedUpdateName $failedUpdateName
            $rollbackState = Read-ArtifactSigningRollbackState `
                -RollbackRoot $rollbackStateRoot
            Assert-True `
                -Condition (
                    $rollbackState.State -ceq $transition[2] -and
                    $rollbackState.FailedUpdateName -ceq $failedUpdateName -and
                    $rollbackState.FailedUpdateDisposition -ceq
                        $transition[3]) `
                -Message 'The rollback transaction state was not committed exactly.'
            $rollbackPreviousPath = Join-Path $rollbackStateRoot `
                'rollback-state.previous'
            Assert-True `
                -Condition (-not (Test-Path -LiteralPath `
                    $rollbackPreviousPath)) `
                -Message 'The prior rollback transaction state was not cleaned.'
            if ($transition[2] -ceq 'Prepared') {
                Copy-Item -LiteralPath (Join-Path $rollbackStateRoot `
                    'rollback-state.txt') `
                    -Destination $rollbackPreviousPath
                $rollbackBuiltIn = Get-ArtifactSigningBuiltInSids
                Set-ArtifactSigningExactAcl `
                    -Path $rollbackPreviousPath `
                    -FullControl @(
                        $rollbackBuiltIn.System,
                        $rollbackBuiltIn.Administrators) `
                    -ReadAndExecute @() -Directory $false
            }
        }
        Assert-Throws `
            -Action {
                Write-ArtifactSigningRollbackState `
                    -RollbackRoot $rollbackStateRoot `
                    -ExpectedState Prepared `
                    -NewState CurrentMoved `
                    -FailedUpdateName $failedUpdateName `
                    -ExpectedDisposition Pending `
                    -NewDisposition Retained
            } `
            -Message 'A stale rollback transaction transition was accepted.'
        $rollbackStatePath = Join-Path $rollbackStateRoot `
            'rollback-state.txt'
        [IO.File]::WriteAllText(
            $rollbackStatePath,
            "Format=ArtifactSigningRollbackStateV1`n" +
            "State=Verified`n" +
            "FailedUpdateName=$failedUpdateName`n" +
            "FailedUpdateDisposition=Retained`n`n",
            [Text.Encoding]::ASCII)
        Assert-Throws `
            -Action {
                Read-ArtifactSigningRollbackState `
                    -RollbackRoot $rollbackStateRoot | Out-Null
            } `
            -Message 'Malformed rollback transaction state was accepted.'

        foreach ($scenario in @(
                @{ Name = 'retained'; SeedLive = $true; InterruptCurrent = $false; InterruptPrior = $false },
                @{ Name = 'absent'; SeedLive = $false; InterruptCurrent = $false; InterruptPrior = $false },
                @{ Name = 'current-interrupted'; SeedLive = $true; InterruptCurrent = $true; InterruptPrior = $false },
                @{ Name = 'prior-interrupted'; SeedLive = $true; InterruptCurrent = $false; InterruptPrior = $true })) {
            $moveRoot = Join-Path $aclRuleTestRoot `
                "rollback-move-$($scenario.Name)"
            $moveRollbackRoot = Join-Path $moveRoot 'rollback'
            $movePrior = Join-Path $moveRollbackRoot 'ArtifactSigning'
            $moveLive = Join-Path $moveRoot 'ArtifactSigning'
            $moveFailedName = 'ArtifactSigning.failed-20260803050607'
            $moveFailed = Join-Path $moveRoot $moveFailedName
            [IO.Directory]::CreateDirectory($movePrior) | Out-Null
            [IO.File]::WriteAllText(
                (Join-Path $movePrior 'generation.txt'),
                'prior')
            if ($scenario.SeedLive) {
                [IO.Directory]::CreateDirectory($moveLive) | Out-Null
                [IO.File]::WriteAllText(
                    (Join-Path $moveLive 'generation.txt'),
                    'current')
            }
            Write-ArtifactSigningRollbackState `
                -RollbackRoot $moveRollbackRoot `
                -ExpectedState Absent -ExpectedDisposition None `
                -NewState Prepared -NewDisposition Pending `
                -FailedUpdateName $moveFailedName
            $movePaths = [pscustomobject]@{
                InstallRoot = $moveLive
                RollbackRoot = $moveRollbackRoot
            }
            $moveState = Read-ArtifactSigningRollbackState `
                -RollbackRoot $moveRollbackRoot
            if ($scenario.InterruptCurrent) {
                Move-Item -LiteralPath $moveLive `
                    -Destination $moveFailed
            }
            $moveState = Move-ArtifactSigningRollbackCurrentGeneration `
                -Paths $movePaths `
                -FailedUpdatePath $moveFailed `
                -Transaction $moveState
            $expectedDisposition = if ($scenario.SeedLive) {
                'Retained'
            }
            else {
                'Absent'
            }
            Assert-True `
                -Condition (
                    $moveState.State -ceq 'CurrentMoved' -and
                    $moveState.FailedUpdateDisposition -ceq
                        $expectedDisposition -and
                    -not (Test-Path -LiteralPath $moveLive) -and
                    ((Test-Path -LiteralPath $moveFailed) -eq
                        $scenario.SeedLive)) `
                -Message 'The current-generation rollback move was not recoverable.'
            if ($scenario.InterruptPrior) {
                Move-Item -LiteralPath $movePrior `
                    -Destination $moveLive
            }
            $moveState = Move-ArtifactSigningRollbackPriorGeneration `
                -Paths $movePaths `
                -RollbackInstallation $movePrior `
                -FailedUpdatePath $moveFailed `
                -Transaction $moveState
            Assert-True `
                -Condition (
                    $moveState.State -ceq 'PriorMoved' -and
                    (Test-Path -LiteralPath $moveLive) -and
                    -not (Test-Path -LiteralPath $movePrior) -and
                    [IO.File]::ReadAllText(
                        (Join-Path $moveLive 'generation.txt')) -ceq
                        'prior') `
                -Message 'The prior-generation rollback move was not recoverable.'
        }

        $missingRoot = Join-Path $aclRuleTestRoot `
            'rollback-move-missing-retained'
        $missingRollback = Join-Path $missingRoot 'rollback'
        $missingPrior = Join-Path $missingRollback 'ArtifactSigning'
        $missingLive = Join-Path $missingRoot 'ArtifactSigning'
        $missingFailedName = 'ArtifactSigning.failed-20260803060708'
        $missingFailed = Join-Path $missingRoot $missingFailedName
        [IO.Directory]::CreateDirectory($missingPrior) | Out-Null
        [IO.Directory]::CreateDirectory($missingLive) | Out-Null
        Write-ArtifactSigningRollbackState `
            -RollbackRoot $missingRollback `
            -ExpectedState Absent -ExpectedDisposition None `
            -NewState Prepared -NewDisposition Pending `
            -FailedUpdateName $missingFailedName
        $missingPaths = [pscustomobject]@{
            InstallRoot = $missingLive
            RollbackRoot = $missingRollback
        }
        $missingState = Move-ArtifactSigningRollbackCurrentGeneration `
            -Paths $missingPaths `
            -FailedUpdatePath $missingFailed `
            -Transaction (Read-ArtifactSigningRollbackState `
                -RollbackRoot $missingRollback)
        Remove-ArtifactSigningDirectTree -Path $missingFailed
        Assert-Throws `
            -Action {
                Move-ArtifactSigningRollbackPriorGeneration `
                    -Paths $missingPaths `
                    -RollbackInstallation $missingPrior `
                    -FailedUpdatePath $missingFailed `
                    -Transaction $missingState | Out-Null
            } `
            -Message 'Missing retained failed-update evidence was accepted.'
        Assert-True `
            -Condition (
                (Test-Path -LiteralPath $missingPrior) -and
                -not (Test-Path -LiteralPath $missingLive)) `
            -Message 'A failed-closed rollback changed the prior generation.'

        $fileRules = @(
            (New-TestAclRule -Sid $builtIn.System `
                -Inheritance ([Security.AccessControl.InheritanceFlags]::ContainerInherit) `
                -Propagation ([Security.AccessControl.PropagationFlags]::InheritOnly)),
            (New-TestAclRule -Sid $builtIn.Administrators `
                -Inheritance ([Security.AccessControl.InheritanceFlags]::ContainerInherit) `
                -Propagation ([Security.AccessControl.PropagationFlags]::InheritOnly)),
            (New-TestAclRule -Sid $readSid `
                -Rights $persistedReadAndExecute `
                -Inheritance ([Security.AccessControl.InheritanceFlags]::ContainerInherit) `
                -Propagation ([Security.AccessControl.PropagationFlags]::InheritOnly))
        )
        $script:aclTestDescriptor = New-TestAclDescriptor `
            -Rules $fileRules -Owner $builtIn.System
        Test-ArtifactSigningExactAcl -Path $aclRuleTestFile `
            -FullControl $admins -ReadAndExecute @($readSid) `
            -Directory $false

        $script:aclTestDescriptor = New-TestAclDescriptor `
            -Rules @(
                (New-TestAclRule -Sid $builtIn.System),
                (New-TestAclRule -Sid $builtIn.Administrators),
                (New-TestAclRule -Sid $readSid `
                    -Rights ([Security.AccessControl.FileSystemRights]::ReadAndExecute))
            ) -Owner $builtIn.System
        $missingSynchronizeFailure = $null
        try {
            Test-ArtifactSigningExactAcl -Path $aclRuleTestRoot `
                -FullControl $admins -ReadAndExecute @($readSid) `
                -Directory $true
        }
        catch {
            $missingSynchronizeFailure = [string]$_.Exception.Message
        }
        Assert-True `
            -Condition (
                $missingSynchronizeFailure -ceq
                    'ArtifactSigningExactAclFailed:Rules') `
            -Message 'A non-canonical read/execute allow mask was accepted.'

        $invalidRuleSets = @(
            @(
                (New-TestAclRule -Sid $builtIn.System -Inherited $true),
                (New-TestAclRule -Sid $builtIn.Administrators)
            ),
            @(
                (New-TestAclRule -Sid $builtIn.System `
                    -AccessType ([Security.AccessControl.AccessControlType]::Deny)),
                (New-TestAclRule -Sid $builtIn.Administrators)
            ),
            @(
                (New-TestAclRule -Sid $builtIn.System),
                (New-TestAclRule -Sid $builtIn.System),
                (New-TestAclRule -Sid $builtIn.Administrators)
            ),
            @(
                (New-TestAclRule -Sid $readSid),
                (New-TestAclRule -Sid $builtIn.Administrators)
            ),
            @(
                (New-TestAclRule -Sid $builtIn.System `
                    -Rights ([Security.AccessControl.FileSystemRights]::ReadAndExecute)),
                (New-TestAclRule -Sid $builtIn.Administrators)
            ),
            @(
                (New-TestAclRule -Sid $builtIn.System `
                    -Inheritance ([Security.AccessControl.InheritanceFlags]::None)),
                (New-TestAclRule -Sid $builtIn.Administrators)
            )
        )
        foreach ($invalidRules in $invalidRuleSets) {
            $script:aclTestDescriptor = New-TestAclDescriptor `
                -Rules $invalidRules -Owner $builtIn.System
            $ruleFailure = $null
            try {
                Test-ArtifactSigningExactAcl -Path $aclRuleTestRoot `
                    -FullControl $admins -ReadAndExecute @() -Directory $true
            }
            catch {
                $ruleFailure = [string]$_.Exception.Message
            }
            Assert-True `
                -Condition (
                    $ruleFailure -ceq 'ArtifactSigningExactAclFailed:Rules') `
                -Message 'An invalid root ACL rule set was not rejected safely.'
        }

        Add-Type -TypeDefinition @'
using System;

public sealed class ArtifactSigningThrowingAclRuleTest
{
    public object IdentityReference
    {
        get
        {
            throw new InvalidOperationException(
                "sensitive native rule diagnostic");
        }
    }
}
'@
        $throwingRule = [ArtifactSigningThrowingAclRuleTest]::new()
        $script:aclTestDescriptor = New-TestAclDescriptor `
            -Rules @(
                $throwingRule,
                (New-TestAclRule -Sid $builtIn.Administrators)
            ) -Owner $builtIn.System
        $rulePropertyFailure = $null
        try {
            Test-ArtifactSigningControlAcls -Paths ([pscustomobject]@{
                ControlRoot = $aclRuleTestRoot
                InstalledInventory = (Join-Path $aclRuleTestRoot 'inventory.txt')
                InstalledDeployment = (Join-Path $aclRuleTestRoot 'deployment.txt')
                InstalledReleaseDigest = (Join-Path $aclRuleTestRoot 'release.txt')
            })
        }
        catch {
            $rulePropertyFailure = [string]$_.Exception.Message
        }
        Assert-True `
            -Condition (
                $rulePropertyFailure -ceq
                    'ArtifactSigningControlAclFailed:RootRules') `
            -Message 'A native rule-property failure was not safely classified.'
    }
    finally {
        Remove-Item Function:\Get-Acl -Force -ErrorAction SilentlyContinue
        Remove-Variable aclTestDescriptor -Scope Script `
            -Force -ErrorAction SilentlyContinue
        Remove-Variable aclTestDescriptorsByPath -Scope Script `
            -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $aclRuleTestRoot -Recurse -Force
    }

    function New-TestServiceProperties {
        param(
            [Parameter(Mandatory)][string] $ImagePath,
            [Parameter(Mandatory)][string] $ObjectName,
            [switch] $IncludeDependency,
            [object] $Dependency
        )

        $properties = [ordered]@{
            ImagePath = $ImagePath
            ObjectName = $ObjectName
            Start = 2
            DelayedAutoStart = 1
            ServiceSidType = 1
            FailureActionsOnNonCrashFailures = 1
            FailureActions = [byte[]]@(1)
        }
        if ($IncludeDependency) {
            $properties.DependOnService = $Dependency
        }
        return [pscustomobject]$properties
    }

    $serviceTestRoot = Join-Path (
        [IO.Path]::GetTempPath()
    ) "artifact-signing-service-test-$([Guid]::NewGuid().ToString('N'))"
    $serviceTestPaths = [pscustomobject]@{
        WorkerRoot = Join-Path $serviceTestRoot 'Worker'
        GatewayRoot = Join-Path $serviceTestRoot 'Gateway'
    }
    $localServiceTestDeployment = [pscustomobject]@{
        IsMicrosoftArtifactSigning = $false
    }
    $workerImage = '"{0}"' -f (
        Join-Path $serviceTestPaths.WorkerRoot 'ArtifactSigning.Worker.exe')
    $gatewayImage = '"{0}"' -f (
        Join-Path $serviceTestPaths.GatewayRoot 'ArtifactSigning.Gateway.exe')
    function New-ValidWorkerServiceProperties {
        New-TestServiceProperties `
            -ImagePath $workerImage `
            -ObjectName 'NT SERVICE\ArtifactSigningWorker' `
            -IncludeDependency `
            -Dependency ([string[]]@('W32Time'))
    }
    function New-ValidGatewayServiceProperties {
        New-TestServiceProperties `
            -ImagePath $gatewayImage `
            -ObjectName 'NT SERVICE\ArtifactSigningGateway' `
            -IncludeDependency `
            -Dependency ([string[]]@('ArtifactSigningWorker'))
    }
    try {
        function Get-Service {
            [CmdletBinding()]
            param([Parameter(Mandatory)][string] $Name)

            if ($Name -cnotin @(
                    'ArtifactSigningWorker',
                    'ArtifactSigningGateway')) {
                throw 'sensitive native service diagnostic'
            }
            return [pscustomobject]@{ Name = $Name }
        }
        function Get-ItemProperty {
            [CmdletBinding()]
            param([Parameter(Mandatory)][string] $LiteralPath)

            if ($LiteralPath.EndsWith(
                    '\ArtifactSigningWorker',
                    [StringComparison]::Ordinal)) {
                return $script:workerServiceTestProperties
            }
            if ($LiteralPath.EndsWith(
                    '\ArtifactSigningGateway',
                    [StringComparison]::Ordinal)) {
                return $script:gatewayServiceTestProperties
            }
            throw 'sensitive native registry diagnostic'
        }

        $script:workerServiceTestProperties =
            New-ValidWorkerServiceProperties
        $script:gatewayServiceTestProperties =
            New-ValidGatewayServiceProperties
        Test-ArtifactSigningServiceDefinitions `
            -Paths $serviceTestPaths `
            -Deployment $localServiceTestDeployment

        $script:workerServiceTestProperties =
            New-TestServiceProperties `
                -ImagePath $workerImage `
                -ObjectName 'NT SERVICE\ArtifactSigningWorker' `
                -IncludeDependency `
                -Dependency 'UnexpectedService'
        $workerDependencyFailure = $null
        try {
            Test-ArtifactSigningServiceDefinitions `
                -Paths $serviceTestPaths `
                -Deployment $localServiceTestDeployment
        }
        catch {
            $workerDependencyFailure = [string]$_.Exception.Message
        }
        Assert-True `
            -Condition (
                $workerDependencyFailure -ceq
                    'ArtifactSigningServiceDefinitionValidationFailed:WorkerDependency') `
            -Message 'An explicit worker dependency was not rejected safely.'

        $script:workerServiceTestProperties =
            New-ValidWorkerServiceProperties
        foreach ($gatewayDependency in @(
                $null,
                [string[]]@('UnexpectedService'),
                [string[]]@(
                    'ArtifactSigningWorker',
                    'UnexpectedService'))) {
            $script:gatewayServiceTestProperties = if (
                $null -eq $gatewayDependency) {
                New-TestServiceProperties `
                    -ImagePath $gatewayImage `
                    -ObjectName 'NT SERVICE\ArtifactSigningGateway'
            }
            else {
                New-TestServiceProperties `
                    -ImagePath $gatewayImage `
                    -ObjectName 'NT SERVICE\ArtifactSigningGateway' `
                    -IncludeDependency `
                    -Dependency $gatewayDependency
            }
            $gatewayDependencyFailure = $null
            try {
                Test-ArtifactSigningServiceDefinitions `
                    -Paths $serviceTestPaths `
                    -Deployment $localServiceTestDeployment
            }
            catch {
                $gatewayDependencyFailure = [string]$_.Exception.Message
            }
            Assert-True `
                -Condition (
                    $gatewayDependencyFailure -ceq
                        'ArtifactSigningServiceDefinitionValidationFailed:GatewayDependency') `
                -Message 'An invalid gateway dependency was not rejected safely.'
        }

        foreach ($role in @('Worker', 'Gateway')) {
            $script:workerServiceTestProperties =
                New-ValidWorkerServiceProperties
            $script:gatewayServiceTestProperties =
                New-ValidGatewayServiceProperties
            if ($role -ceq 'Worker') {
                $script:workerServiceTestProperties =
                    New-TestServiceProperties `
                        -ImagePath '"C:\UnexpectedWorker.exe"' `
                        -ObjectName 'NT SERVICE\ArtifactSigningWorker' `
                        -IncludeDependency `
                        -Dependency ([string[]]@('W32Time'))
            }
            else {
                $script:gatewayServiceTestProperties =
                    New-TestServiceProperties `
                        -ImagePath '"C:\UnexpectedGateway.exe"' `
                        -ObjectName 'NT SERVICE\ArtifactSigningGateway' `
                        -IncludeDependency `
                        -Dependency ([string[]]@('ArtifactSigningWorker'))
            }
            $imagePathFailure = $null
            try {
                Test-ArtifactSigningServiceDefinitions `
                    -Paths $serviceTestPaths `
                    -Deployment $localServiceTestDeployment
            }
            catch {
                $imagePathFailure = [string]$_.Exception.Message
            }
            Assert-True `
                -Condition (
                    $imagePathFailure -ceq
                        ('ArtifactSigningServiceDefinitionValidationFailed:' +
                            "${role}ImagePath")) `
                -Message 'An invalid service image path was not rejected safely.'
        }
    }
    finally {
        Remove-Item Function:\Get-Service -Force -ErrorAction SilentlyContinue
        Remove-Item Function:\Get-ItemProperty `
            -Force -ErrorAction SilentlyContinue
        Remove-Item Function:\New-ValidWorkerServiceProperties `
            -Force -ErrorAction SilentlyContinue
        Remove-Item Function:\New-ValidGatewayServiceProperties `
            -Force -ErrorAction SilentlyContinue
        Remove-Variable workerServiceTestProperties -Scope Script `
            -Force -ErrorAction SilentlyContinue
        Remove-Variable gatewayServiceTestProperties -Scope Script `
            -Force -ErrorAction SilentlyContinue
    }

    $originalWorkerServiceName = $script:WorkerServiceName
    $originalGatewayServiceName = $script:GatewayServiceName
    $nativeServiceSuffix = [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $script:WorkerServiceName = "ArtifactSigningWorkerTest$nativeServiceSuffix"
    $script:GatewayServiceName = "ArtifactSigningGatewayTest$nativeServiceSuffix"
    $nativeServiceTestRoot = Join-Path (
        [IO.Path]::GetTempPath()
    ) "artifact signing native service test $nativeServiceSuffix"
    $nativeServiceTestPaths = [pscustomobject]@{
        WorkerRoot = Join-Path $nativeServiceTestRoot 'Worker'
        GatewayRoot = Join-Path $nativeServiceTestRoot 'Gateway'
    }
    try {
        Install-ArtifactSigningServiceDefinitions `
            -Paths $nativeServiceTestPaths `
            -Deployment $localServiceTestDeployment

        $nativeExpected = @{
            $script:WorkerServiceName = @{
                ImagePath = '"{0}"' -f (Join-Path `
                    $nativeServiceTestPaths.WorkerRoot `
                    'ArtifactSigning.Worker.exe')
                ObjectName = "NT SERVICE\$($script:WorkerServiceName)"
                Dependency = 'W32Time'
            }
            $script:GatewayServiceName = @{
                ImagePath = '"{0}"' -f (Join-Path `
                    $nativeServiceTestPaths.GatewayRoot `
                    'ArtifactSigning.Gateway.exe')
                ObjectName = "NT SERVICE\$($script:GatewayServiceName)"
                Dependency = $script:WorkerServiceName
            }
        }
        foreach ($name in $nativeExpected.Keys) {
            $properties = Get-ItemProperty -LiteralPath `
                "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
            $dependencyProperty =
                $properties.PSObject.Properties['DependOnService']
            if ($null -eq $nativeExpected[$name].Dependency) {
                Assert-True -Condition ($null -eq $dependencyProperty) `
                    -Message 'The native worker dependency is not absent.'
            }
            else {
                $dependencies = @()
                if ($null -ne $dependencyProperty) {
                    $dependencies = @($dependencyProperty.Value)
                }
                Assert-True `
                    -Condition (
                        $dependencies.Count -eq 1 -and
                        [string]$dependencies[0] -ceq
                            $nativeExpected[$name].Dependency) `
                    -Message 'The native gateway dependency is invalid.'
            }
            Assert-True `
                -Condition (
                    $properties.ImagePath -ceq
                        $nativeExpected[$name].ImagePath) `
                -Message 'The native service image path is invalid.'
            Assert-True `
                -Condition (
                    $properties.ObjectName -ceq
                        $nativeExpected[$name].ObjectName) `
                -Message 'The native service identity is invalid.'
            Assert-True `
                -Condition (
                    $properties.Start -eq 2 -and
                    $properties.DelayedAutoStart -eq 1) `
                -Message 'The native service start mode is invalid.'
            Assert-True `
                -Condition ($properties.ServiceSidType -eq 1) `
                -Message 'The native service SID type is invalid.'
            Assert-True `
                -Condition (
                    $properties.FailureActionsOnNonCrashFailures -eq 1 -and
                    $null -ne $properties.FailureActions) `
                -Message 'The native service recovery settings are invalid.'
        }
        Test-ArtifactSigningServiceDefinitions `
            -Paths $nativeServiceTestPaths `
            -Deployment $localServiceTestDeployment
    }
    finally {
        try {
            Remove-ArtifactSigningServiceDefinitions
        }
        finally {
            $script:WorkerServiceName = $originalWorkerServiceName
            $script:GatewayServiceName = $originalGatewayServiceName
        }
    }
}

$installerSource = [IO.File]::ReadAllText(
    (Join-Path $installerRoot 'ArtifactSigning.Installer.ps1'))
$installSource = [IO.File]::ReadAllText(
    (Join-Path $installerRoot 'install-artifact-signing-service.ps1'))
$verifySource = [IO.File]::ReadAllText(
    (Join-Path $installerRoot 'verify-artifact-signing-service.ps1'))
$rollbackSource = [IO.File]::ReadAllText(
    (Join-Path $installerRoot 'rollback-artifact-signing-service.ps1'))
foreach ($updateVerificationContract in @(
        'Test-ArtifactSigningControlAcls -Paths $paths',
        'Test-ArtifactSigningInstalledVerifierExecutionTrust -Paths $paths',
        'Test-ArtifactSigningInstalledPayload -Paths $paths',
        '$paths.InstallerRoot')) {
    Assert-True `
        -Condition $installSource.Contains($updateVerificationContract) `
        -Message 'Update does not verify the protected installed generation.'
}
$updateVerificationIndex = $installSource.IndexOf(
    '$phase = ''UpdatePreparation''',
    [StringComparison]::Ordinal)
foreach ($orderedUpdateContract in @(
        'Test-ArtifactSigningControlAcls -Paths $paths',
        'Test-ArtifactSigningInstalledVerifierExecutionTrust -Paths $paths',
        'Test-ArtifactSigningInstalledPayload -Paths $paths',
        '$paths.InstallerRoot')) {
    $nextUpdateVerificationIndex = $installSource.IndexOf(
        $orderedUpdateContract,
        $updateVerificationIndex + 1,
        [StringComparison]::Ordinal)
    Assert-True `
        -Condition (
            $updateVerificationIndex -ge 0 -and
            $nextUpdateVerificationIndex -gt $updateVerificationIndex) `
        -Message 'Update verification is not ordered before installed execution.'
    $updateVerificationIndex = $nextUpdateVerificationIndex
}
Assert-True `
    -Condition ([regex]::IsMatch(
        $installSource,
        '\$paths\.InstallerRoot[\s\S]{0,120}' +
        "'verify-artifact-signing-service\.ps1'")) `
    -Message 'Update does not invoke the installed generation verifier.'
Assert-True `
    -Condition ($installSource.Contains(
        '$existingDeployment = Read-ArtifactSigningReviewedRollbackDeployment')) `
    -Message 'Update does not parse the installed deployment through the reviewed compatibility boundary.'
Assert-True `
    -Condition ([regex]::Matches(
        $installSource,
        'Read-ArtifactSigningReviewedRollbackDeployment').Count -eq 2) `
    -Message 'The update path invokes the reviewed legacy rollback parser ambiguously.'
Assert-True `
    -Condition (-not $installSource.Contains(
        '$deployment = Read-ArtifactSigningReviewedRollbackDeployment')) `
    -Message 'The staged deployment validation accepted legacy installer versions.'
$rollbackDeploymentValidationIndex = $installSource.IndexOf(
    'Test-ArtifactSigningInstalledPayload -Paths $rollbackNextPaths',
    [StringComparison]::Ordinal)
$reviewedRollbackDeploymentIndex = $installSource.IndexOf(
    'Read-ArtifactSigningReviewedRollbackDeployment',
    $rollbackDeploymentValidationIndex + 1,
    [StringComparison]::Ordinal)
Assert-True `
    -Condition (
        $rollbackDeploymentValidationIndex -ge 0 -and
        $reviewedRollbackDeploymentIndex -gt
            $rollbackDeploymentValidationIndex) `
    -Message 'The legacy rollback deployment parser runs before copied payload verification.'
foreach ($controlReplacementContract in @(
        '$existingDeployment.IsReadOnly = $false',
        '$installedDeployment.IsReadOnly = $false')) {
    Assert-True `
        -Condition $installerSource.Contains($controlReplacementContract) `
        -Message 'Read-only deployment control replacement is incomplete.'
}
foreach ($rollbackContract in @(
        'Test-ArtifactSigningControlAcls -Paths $rollbackPaths',
        'Test-ArtifactSigningInstalledVerifierExecutionTrust -Paths $rollbackPaths',
        'Test-ArtifactSigningInstalledPayload -Paths $rollbackPaths',
        '$rollbackPaths.InstallerRoot',
        '$paths.InstallerRoot')) {
    Assert-True `
        -Condition $rollbackSource.Contains($rollbackContract) `
        -Message 'Rollback does not verify and invoke the prior generation safely.'
}
foreach ($nativeLaunchContract in @(
        '$startInfo.UseShellExecute = $false',
        '$startInfo.RedirectStandardOutput = $true',
        '$startInfo.RedirectStandardError = $true',
        '$process.BeginOutputReadLine()',
        '$process.BeginErrorReadLine()',
        '$process.WaitForExit(30000)')) {
    Assert-True `
        -Condition $installerSource.Contains($nativeLaunchContract) `
        -Message 'The direct service-control launch contract is incomplete.'
}
Assert-True `
    -Condition (-not $installerSource.Contains(
        '$bytes | Where-Object { $_ -gt 127 }')) `
    -Message 'A byte-validation condition still has ambiguous pipeline precedence.'
foreach ($target in @(
        'Profiles',
        'RuleSet',
        'GatewayIn',
        'WorkerTimestamp',
        'WorkerReadiness',
        'Time',
        'GatewayRevocation',
        'WorkerRevocation',
        'WorkerMicrosoftCertificateStatus',
        'WorkerMicrosoftCertificateStatusKeywords')) {
    Assert-True `
        -Condition $installerSource.Contains($target) `
        -Message "A fixed firewall validation target is missing: $target"
    Assert-True `
        -Condition (
            $installSource.Contains($target) -and
            $verifySource.Contains($target)) `
        -Message "A fixed firewall failure mapping is missing: $target"
}
Assert-True `
    -Condition $installerSource.Contains(
        'throw "ArtifactSigningFirewallPolicyFailed:$($definition.Target)"') `
    -Message 'Firewall filters do not use a fixed target marker.'
Assert-True `
    -Condition (
        $installerSource.Contains(
            '-Program $Deployment.Values.SignToolPath | Out-Null') -and
        $installerSource.Contains(
            'Program = $Deployment.Values.SignToolPath') -and
        $installerSource.Contains("Service = 'Any'")) `
    -Message (
        'Timestamp egress is not restricted to the configured SignTool ' +
        'process without an inapplicable service filter.')
foreach ($mappingSource in @($installSource, $verifySource)) {
    Assert-True `
        -Condition $mappingSource.Contains(
            '$failedPhase = "FirewallPolicy$($Matches[1])"') `
        -Message 'Firewall failures are not mapped to fixed phases.'
}
foreach ($target in @('Gateway', 'Worker', 'Installer')) {
    Assert-True `
        -Condition $installerSource.Contains("Target = '$target'") `
        -Message "A fixed Event Log source target is missing: $target"
    Assert-True `
        -Condition (
            $installSource.Contains($target) -and
            $verifySource.Contains($target)) `
        -Message "A fixed Event Log source mapping is missing: $target"
}
Assert-True `
    -Condition $installerSource.Contains(
        '[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames') `
    -Message 'The Event Log message path is not read without expansion.'
Assert-True `
    -Condition (
        [regex]::Matches(
            $installerSource,
            'function Register-ArtifactSigningEventSources[\s\S]{0,1500}' +
            'Test-ArtifactSigningEventSources').Count -eq 1) `
    -Message 'Event Log sources are not verified immediately after writing.'
foreach ($mappingSource in @($installSource, $verifySource)) {
    Assert-True `
        -Condition $mappingSource.Contains(
            '$failedPhase = "EventSources$($Matches[1])"') `
        -Message 'Event Log source failures are not mapped to fixed phases.'
}
Assert-True `
    -Condition (
        $installerSource.Contains('$certificates = @()') -and
        -not $installerSource.Contains('$matches = @()')) `
    -Message (
        'The certificate resolver collides with the automatic ' +
        'PowerShell Matches variable.')
foreach ($phase in @(
        'HostValidation',
        'ControlAcls',
        'InstalledPayload',
        'DeploymentValidation',
        'ServiceDefinitions',
        'InstallationAcls',
        'StateDirectories',
        'KeyAcls',
        'SignToolValidation',
        'ComponentVersionValidation',
        'FirewallPolicy',
        'TimePolicy',
        'EventSources',
        'ServiceStatus',
        'AuditEvent')) {
    Assert-True `
        -Condition $verifySource.Contains("`$phase = '$phase'") `
        -Message "A fixed appliance verification phase is missing: $phase"
}
Assert-True `
    -Condition $verifySource.Contains(
        'throw "ArtifactSigningApplianceVerifyFailed:$failedPhase"') `
    -Message 'The appliance verifier does not return only its fixed failure phase.'
foreach ($phase in @('Root', 'Inventory', 'Deployment', 'ReleaseDigest')) {
    Assert-True `
        -Condition $installerSource.Contains(
            "ArtifactSigningControlAclFailed:$phase") `
        -Message "A fixed control ACL verification phase is missing: $phase"
    Assert-True `
        -Condition $verifySource.Contains(
            "ControlAcls$phase") `
        -Message "A fixed control ACL failure mapping is missing: $phase"
}
foreach ($phase in @(
        'RootDirectPath',
        'RootSecurityDescriptor',
        'RootOwnerOrProtection',
        'RootRules')) {
    Assert-True `
        -Condition $installerSource.Contains(
            "ArtifactSigningControlAclFailed:$phase") `
        -Message "A fixed root ACL verification reason is missing: $phase"
    Assert-True `
        -Condition $verifySource.Contains("ControlAcls$phase") `
        -Message "A fixed root ACL failure mapping is missing: $phase"
}
foreach ($phase in @(
        'WorkerDependency',
        'GatewayDependency',
        'WorkerImagePath',
        'GatewayImagePath')) {
    Assert-True `
        -Condition $installerSource.Contains(
            "ArtifactSigningServiceDefinitionValidationFailed:$phase") `
        -Message (
            'A fixed service-definition reason is missing: ' +
            $phase)
    Assert-True `
        -Condition $verifySource.Contains("ServiceDefinitions$phase") `
        -Message (
            'A fixed service-definition mapping is missing: ' +
            $phase)
}
foreach ($target in @(
        'InstallRoot',
        'GatewayRoot',
        'WorkerRoot',
        'InstallerRoot',
        'GatewayFiles',
        'WorkerFiles',
        'InstallerFiles')) {
    Assert-True `
        -Condition $installerSource.Contains("'$target'") `
        -Message (
            'A fixed installation ACL target is missing: ' +
            $target)
    Assert-True `
        -Condition $verifySource.Contains($target) `
        -Message (
            'A fixed installation ACL verification mapping is missing: ' +
            $target)
}
Assert-True `
    -Condition $installerSource.Contains(
        'throw "ArtifactSigningInstallationAclFailed:$Target"') `
    -Message 'Installation ACL failures do not use a fixed target marker.'
Assert-True `
    -Condition $verifySource.Contains(
        '$failedPhase = "InstallationAcls$($Matches[1])"') `
    -Message 'Installation ACL failures are not mapped to fixed phases.'
Assert-True `
    -Condition $installerSource.Contains(
        '[Security.AccessControl.FileSystemRights]::Synchronize') `
    -Message 'The persisted read/execute ACL mask is not canonicalized.'
foreach ($operation in @(
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
        'GatewayRecoveryFlag')) {
    Assert-True `
        -Condition $installerSource.Contains("-Operation $operation") `
        -Message "A fixed service-definition operation is missing: $operation"
}
Assert-True `
    -Condition (
        [regex]::Matches(
            $installerSource,
            '-Operation (Worker|Gateway)Create -Arguments @\(' +
            '[\s\S]{0,250}disabled').Count -eq 2) `
    -Message 'A service is not initially created in the disabled state.'
Assert-True `
    -Condition (
        [regex]::Matches(
            $installerSource,
            '-Operation (Worker|Gateway)Identity -Arguments @\(' +
            '[\s\S]{0,200}NT SERVICE\\').Count -eq 2) `
    -Message 'A virtual service identity is not configured separately.'
Assert-True `
    -Condition (
        [regex]::Matches(
            $installerSource,
            '-Operation (Worker|Gateway)StartMode -Arguments @\(' +
            '[\s\S]{0,200}delayed-auto').Count -eq 2) `
    -Message 'A service is not enabled only after identity assignment.'
foreach ($timePolicyContract in @(
        "return @('W32Time')",
        "return @('himds', 'W32Time')",
        "'/syncfromflags:manual'",
        "'/resync', '/rediscover'",
        'Set-Service -Name W32Time -StartupType Automatic',
        'Test-ArtifactSigningTimePolicy -Deployment $Deployment')) {
    Assert-True `
        -Condition $installerSource.Contains($timePolicyContract) `
        -Message "A Windows Time policy contract is missing: $timePolicyContract"
}
foreach ($managedFirewallContract in @(
        "'ArtifactSigning-Worker-Himds-Loopback-Out'",
        "'ArtifactSigning-SignTool-Himds-Loopback-Out'",
        "-RemoteAddress 127.0.0.1 -RemotePort 40342",
        "'ArtifactSigning-Worker-Microsoft-Out'",
        "'ArtifactSigning-Worker-Microsoft-CertificateStatus-Out'",
        "Fqdn = 'www.microsoft.com'",
        "Fqdn = 'oneocsp.microsoft.com'",
        'New-NetFirewallDynamicKeywordAddress',
        '-RemoteDynamicKeywordAddresses',
        "'ArtifactSigning-Arc-Himds-Out'",
        "'ArtifactSigning-Arc-ArcProxy-Out'",
        'ProcessScopedTlsValidatedInternet')) {
    Assert-True `
        -Condition $installerSource.Contains($managedFirewallContract) `
        -Message "A managed firewall contract is missing: $managedFirewallContract"
}

foreach ($localGroupRemovalContract in @(
        'function Remove-ArtifactSigningLocalGroupMemberBySid',
        '-Member $matches[0] -Confirm:$false',
        'Remove-ArtifactSigningLocalGroupMemberBySid')) {
    Assert-True `
        -Condition $installerSource.Contains(
            $localGroupRemovalContract,
            [StringComparison]::Ordinal) `
        -Message "Missing resolved local-principal removal contract: $localGroupRemovalContract"
}
Assert-True `
    -Condition (-not $installerSource.Contains(
        '-Member $serviceSid -Confirm:$false',
        [StringComparison]::Ordinal)) `
    -Message 'A raw SecurityIdentifier is still passed to Remove-LocalGroupMember.'
foreach ($localGroupAdditionContract in @(
        'function Add-ArtifactSigningLocalGroupMemberBySid',
        '$Sid.Translate([Security.Principal.NTAccount])',
        'Add-ArtifactSigningLocalGroupMemberBySid')) {
    Assert-True `
        -Condition $installerSource.Contains(
            $localGroupAdditionContract,
            [StringComparison]::Ordinal) `
        -Message "Missing translated local-principal addition contract: $localGroupAdditionContract"
}
Assert-True `
    -Condition (-not $installerSource.Contains(
        'Add-LocalGroupMember -Group $group -Member $WorkerSid',
        [StringComparison]::Ordinal)) `
    -Message 'A raw SecurityIdentifier is still passed to Add-LocalGroupMember.'
Assert-True `
    -Condition $installSource.Contains(
        'Set-ArtifactSigningTimePolicy -Deployment $deployment') `
    -Message 'Install does not synchronize the fixed Windows Time policy.'
Assert-True `
    -Condition $verifySource.Contains(
        'Test-ArtifactSigningTimePolicy -Deployment $deployment') `
    -Message 'Installed verification does not validate Windows Time policy.'
Assert-True `
    -Condition $rollbackSource.Contains(
        'Set-ArtifactSigningTimePolicy -Deployment $priorDeployment') `
    -Message 'Rollback does not restore the reviewed Windows Time policy.'

$testRoot = Join-Path (
    [IO.Path]::GetTempPath()
) "artifact-signing-installer-test-$([Guid]::NewGuid().ToString('N'))"
try {
    $testSignToolPath = [IO.Path]::GetFullPath(
        (Join-Path $testRoot 'WindowsKits/x64/signtool.exe'))
    $testWindowsSignToolPath =
        'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'
    foreach ($directory in @(
            $testRoot,
            (Join-Path $testRoot 'Gateway'),
            (Join-Path $testRoot 'Worker'),
            (Join-Path $testRoot 'config'),
            (Join-Path $testRoot 'installer'),
            (Join-Path $testRoot 'profiles'))) {
        [IO.Directory]::CreateDirectory($directory) | Out-Null
    }

    $deployment = @(
        'Format=ArtifactSigningInstallerDeploymentV2'
        'ReleaseVersion=0.1.0'
        "SourceCommit=$('1' * 40)"
        'InstallerVersion=0.4.1'
        'GatewayVersion=0.6.0'
        'WorkerVersion=0.9.0'
        'CliVersion=0.3.0'
        "ProfileSetSha256=$('e' * 64)"
        'GatewayListenAddress=10.20.30.40'
        'GatewayListenPort=8443'
        'GatewayIngressRemoteAddresses=10.20.30.10,10.20.30.11'
        'TimestampRelayAddress=10.20.30.50'
        'TimestampRelayPort=8080'
        'CertificateStatusRemoteAddresses='
        'TimeServerAddresses=10.20.30.1'
        "GatewayTlsCertificateThumbprint=$('A' * 40)"
        "ReceiptCertificateThumbprint=$('B' * 40)"
        "AuthenticodeCertificateThumbprint=$('C' * 40)"
        "SignToolPath=$testWindowsSignToolPath"
        "SignToolSha256=$('d' * 64)"
        'SignToolFileVersion=10.0.26100.1'
    )
    [IO.File]::WriteAllText(
        (Join-Path $testRoot 'deployment.txt'),
        ([string]::Join("`n", $deployment) + "`n"),
        [Text.Encoding]::ASCII)
    [IO.File]::WriteAllText(
        (Join-Path $testRoot 'Gateway/ArtifactSigning.Gateway.exe'),
        'gateway')
    [IO.File]::WriteAllText(
        (Join-Path $testRoot 'Worker/ArtifactSigning.Worker.exe'),
        'worker')
    [IO.File]::WriteAllText(
        (Join-Path $testRoot 'installer/artifact-signctl.exe'),
        'cli')
    [IO.File]::WriteAllText(
        (Join-Path $testRoot 'config/gateway.template.json'),
        '{"Gateway":"__GATEWAY_SERVICE_SID__"}')
    [IO.File]::WriteAllText(
        (Join-Path $testRoot 'config/worker.template.json'),
        '{"Worker":"__WORKER_SERVICE_SID__"}')
    [IO.File]::WriteAllText(
        (Join-Path $testRoot 'profiles/profile-set.lock'),
        ("Format=ArtifactSigningProfileSetLockV1`n" +
        "AbiVersion=1`n" +
        "PackageSetSha256=$('e' * 64)`n" +
        "Package=Example.Profile|1.0.0|$('a' * 64)|$('b' * 64)|$('c' * 64)`n" +
        "Profile=Example.Profile|ExampleEndpointBundleV1|2|$('d' * 64)`n"),
        [Text.Encoding]::ASCII)
    foreach ($name in @(
            'ArtifactSigning.Installer.ps1',
            'install-artifact-signing-service.ps1',
            'verify-artifact-signing-service.ps1',
            'uninstall-artifact-signing-service.ps1',
            'rollback-artifact-signing-service.ps1')) {
        [IO.File]::WriteAllText(
            (Join-Path $testRoot "installer/$name"),
            'exit 0')
    }

    $digest = & (Join-Path $installerRoot `
        'New-ArtifactSigningReleaseInventory.ps1') `
        -PackageRoot $testRoot
    Assert-True `
        -Condition (Test-ArtifactSigningLowerSha256 -Value $digest) `
        -Message 'The package inventory digest is not canonical.'
    $entries = @(Read-ArtifactSigningReleaseInventory `
        -PackageRoot $testRoot `
        -ExpectedInventorySha256 $digest)
    Assert-True -Condition ($entries.Count -eq 12) `
        -Message 'The valid release inventory was not accepted exactly.'

    $parsed = Read-ArtifactSigningDeployment `
        -Path (Join-Path $testRoot 'deployment.txt')
    Test-ArtifactSigningProfileSetLock `
        -Path (Join-Path $testRoot 'profiles/profile-set.lock') `
        -ExpectedProfileSetSha256 $parsed.Values.ProfileSetSha256
    Assert-True `
        -Condition (
            $parsed.GatewayListenPort -eq 8443 -and
            $parsed.GatewayIngressRemoteAddresses.Count -eq 2 -and
            $parsed.CertificateStatusRemoteAddresses.Count -eq 0) `
        -Message 'The valid deployment policy was not parsed exactly.'
    $currentRollbackDeployment = Read-ArtifactSigningReviewedRollbackDeployment `
        -Path (Join-Path $testRoot 'deployment.txt')
    Assert-True `
        -Condition ($currentRollbackDeployment.GatewayListenPort -eq 8443) `
        -Message 'The reviewed rollback deployment parser rejected the current installer version.'

    $managedDeploymentPath = Join-Path $testRoot 'managed-deployment.txt'
    $managedDeployment = @(
        'Format=ArtifactSigningInstallerDeploymentV3'
        'ReleaseVersion=0.1.0'
        "SourceCommit=$('1' * 40)"
        'InstallerVersion=0.4.1'
        'GatewayVersion=0.6.0'
        'WorkerVersion=0.9.0'
        'CliVersion=0.3.0'
        "ProfileSetSha256=$('e' * 64)"
        'GatewayListenAddress=10.20.30.40'
        'GatewayListenPort=8443'
        'GatewayIngressRemoteAddresses=10.20.30.10,10.20.30.11'
        'TimestampRelayAddress='
        'TimestampRelayPort='
        'CertificateStatusRemoteAddresses='
        'TimeServerAddresses=10.20.30.1'
        "GatewayTlsCertificateThumbprint=$('A' * 40)"
        "ReceiptCertificateThumbprint=$('B' * 40)"
        'AuthenticodeCertificateThumbprint='
        "SignToolPath=$testWindowsSignToolPath"
        "SignToolSha256=$('d' * 64)"
        'SignToolFileVersion=10.0.26100.1'
        'SigningProvider=MicrosoftArtifactSigning'
        'DnsServerAddresses=10.20.30.1'
        'ManagedEgressPolicy=ProcessScopedTlsValidatedInternet'
        'MicrosoftArtifactSigningRegion=JapanEast'
        'MicrosoftArtifactSigningAccountName=example-signing'
        'MicrosoftArtifactSigningCertificateProfileName=Example-PublicTrust-Test'
        "MicrosoftArtifactSigningDlibSha256=$('a' * 64)"
        'MicrosoftArtifactSigningDlibFileVersion=1.0.128.0'
        "MicrosoftArtifactSigningClientToolsInventorySha256=$('b' * 64)"
        'MicrosoftArtifactSigningRuntimeMajor=8'
        "MicrosoftArtifactSigningExpectedPublisherSubjectNameSha256=$('c' * 64)"
        'MicrosoftArtifactSigningRequiredPublisherEnhancedKeyUsageOid=1.3.6.1.4.1.311.97.1.2.1'
        "MicrosoftArtifactSigningTrustedPublisherRootThumbprints=$('D' * 40)"
        'MicrosoftArtifactSigningSignToolTimeoutSeconds=120'
        'MicrosoftArtifactSigningAuthenticodeRevocationPolicy=DisposableTestNoCheck'
    )
    [IO.File]::WriteAllText(
        $managedDeploymentPath,
        ([string]::Join("`n", $managedDeployment) + "`n"),
        [Text.Encoding]::ASCII)
    $parsedManaged = Read-ArtifactSigningDeployment `
        -Path $managedDeploymentPath
    Assert-True `
        -Condition (
            $parsedManaged.IsMicrosoftArtifactSigning -and
            $parsedManaged.DnsServerAddresses.Count -eq 1 -and
            $null -eq $parsedManaged.TimestampRelayAddress -and
            $parsedManaged.MicrosoftArtifactSigningRuntimeMajor -eq 8) `
        -Message 'The closed Microsoft Artifact Signing deployment was not parsed exactly.'
    $mixedManagedDeployment = @($managedDeployment | ForEach-Object {
            if ($_ -ceq 'AuthenticodeCertificateThumbprint=') {
                return "AuthenticodeCertificateThumbprint=$('C' * 40)"
            }
            return $_
        })
    [IO.File]::WriteAllText(
        $managedDeploymentPath,
        ([string]::Join("`n", $mixedManagedDeployment) + "`n"),
        [Text.Encoding]::ASCII)
    Assert-Throws -Action {
        Read-ArtifactSigningDeployment -Path $managedDeploymentPath | Out-Null
    } -Message 'A managed deployment with a Local Machine signing key was accepted.'
    Remove-Item -LiteralPath $managedDeploymentPath -Force

    $legacyDeploymentPath = Join-Path $testRoot 'legacy-deployment.txt'
    foreach ($reviewedRollbackVersion in @('0.4.0', '0.3.2')) {
        $legacyDeployment = @($deployment | ForEach-Object {
                if ($_ -ceq 'InstallerVersion=0.4.1') {
                    return "InstallerVersion=$reviewedRollbackVersion"
                }
                return $_
            })
        [IO.File]::WriteAllText(
            $legacyDeploymentPath,
            ([string]::Join("`n", $legacyDeployment) + "`n"),
            [Text.Encoding]::ASCII)
        Assert-Throws -Action {
            Read-ArtifactSigningDeployment `
                -Path $legacyDeploymentPath | Out-Null
        } -Message 'The strict staged deployment parser accepted a legacy installer version.'
        $legacyRollbackDeployment =
            Read-ArtifactSigningReviewedRollbackDeployment `
                -Path $legacyDeploymentPath
        Assert-True `
            -Condition ($legacyRollbackDeployment.GatewayListenPort -eq 8443) `
            -Message (
                'The reviewed rollback deployment parser rejected installer ' +
                "$reviewedRollbackVersion.")
    }
    foreach ($unreviewedInstallerVersion in @('0.2.23', '0.3.1', '0.3.3')) {
        $unreviewedDeployment = @($deployment | ForEach-Object {
                if ($_ -ceq 'InstallerVersion=0.4.1') {
                    return "InstallerVersion=$unreviewedInstallerVersion"
                }
                return $_
            })
        [IO.File]::WriteAllText(
            $legacyDeploymentPath,
            ([string]::Join("`n", $unreviewedDeployment) + "`n"),
            [Text.Encoding]::ASCII)
        Assert-Throws -Action {
            Read-ArtifactSigningReviewedRollbackDeployment `
                -Path $legacyDeploymentPath | Out-Null
        } -Message 'The rollback deployment parser accepted an unreviewed installer version.'
    }

    $deploymentPath = Join-Path $testRoot 'deployment.txt'
    $canonicalDeploymentBytes = [IO.File]::ReadAllBytes($deploymentPath)
    try {
        $nonAsciiDeploymentBytes = [byte[]]::new(
            $canonicalDeploymentBytes.Length)
        [Array]::Copy(
            $canonicalDeploymentBytes,
            $nonAsciiDeploymentBytes,
            $canonicalDeploymentBytes.Length)
        $nonAsciiDeploymentBytes[0] = 128
        [IO.File]::WriteAllBytes(
            $deploymentPath,
            $nonAsciiDeploymentBytes)
        Assert-Throws -Action {
            Read-ArtifactSigningDeployment -Path $deploymentPath | Out-Null
        } -Message 'A non-ASCII deployment file was accepted.'
    }
    finally {
        [IO.File]::WriteAllBytes(
            $deploymentPath,
            $canonicalDeploymentBytes)
    }

    $inventoryPath = Join-Path $testRoot 'release-inventory.txt'
    $canonicalInventoryBytes = [IO.File]::ReadAllBytes($inventoryPath)
    try {
        $nonAsciiInventoryBytes = [byte[]]::new(
            $canonicalInventoryBytes.Length)
        [Array]::Copy(
            $canonicalInventoryBytes,
            $nonAsciiInventoryBytes,
            $canonicalInventoryBytes.Length)
        $nonAsciiInventoryBytes[0] = 128
        [IO.File]::WriteAllBytes(
            $inventoryPath,
            $nonAsciiInventoryBytes)
        $nonAsciiInventoryDigest = (
            Get-FileHash -LiteralPath $inventoryPath -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        Assert-Throws -Action {
            Read-ArtifactSigningReleaseInventory `
                -PackageRoot $testRoot `
                -ExpectedInventorySha256 $nonAsciiInventoryDigest | Out-Null
        } -Message 'A non-ASCII release inventory was accepted.'
    }
    finally {
        [IO.File]::WriteAllBytes(
            $inventoryPath,
            $canonicalInventoryBytes)
    }

    $installedInventoryPath = Join-Path $testRoot 'installed-inventory.txt'
    [IO.File]::WriteAllBytes(
        $installedInventoryPath,
        ([byte[]]@(128)))
    try {
        Assert-Throws -Action {
            Test-ArtifactSigningInstalledPayload -Paths ([pscustomobject]@{
                InstalledInventory = $installedInventoryPath
                InstallRoot = $testRoot
            })
        } -Message 'A non-ASCII installed inventory was accepted.'
    }
    finally {
        Remove-Item -LiteralPath $installedInventoryPath -Force
    }

    foreach ($commandName in @(
            'Set-ArtifactSigningExactAcl',
            'Test-ArtifactSigningExactAcl')) {
        $command = Get-Command -Name $commandName -CommandType Function
        $attributes = @(
            $command.Parameters['ReadAndExecute'].Attributes |
                Where-Object {
                    $_ -is [Management.Automation.AllowEmptyCollectionAttribute]
                }
        )
        Assert-True -Condition ($attributes.Count -eq 1) `
            -Message 'An exact ACL function rejects an intentional empty read set.'
        $fullControlAttributes = @(
            $command.Parameters['FullControl'].Attributes |
                Where-Object {
                    $_ -is [Management.Automation.AllowEmptyCollectionAttribute]
                }
        )
        Assert-True -Condition ($fullControlAttributes.Count -eq 0) `
            -Message 'An exact ACL function permits an empty administrative set.'
    }

    Assert-True `
        -Condition (Test-ArtifactSigningFullyQualifiedPath `
            -Path $testSignToolPath) `
        -Message 'A fully qualified native path was rejected.'
    Assert-True `
        -Condition (-not (Test-ArtifactSigningFullyQualifiedPath `
            -Path 'relative\signtool.exe')) `
        -Message 'A relative path was accepted.'
    Assert-True `
        -Condition (Test-ArtifactSigningWindowsDeploymentPath `
            -Path $testWindowsSignToolPath) `
        -Message 'A Windows deployment path was rejected by the controller.'
    foreach ($invalidWindowsDeploymentPath in @(
            '/tmp/signtool.exe',
            'C:relative\signtool.exe',
            'C:\Windows\..\signtool.exe',
            'C:\Windows\signtool.exe:stream',
            '\\server\share\signtool.exe')) {
        Assert-True `
            -Condition (-not (Test-ArtifactSigningWindowsDeploymentPath `
                -Path $invalidWindowsDeploymentPath)) `
            -Message 'An invalid Windows deployment path was accepted.'
    }
    if ([IO.Path]::DirectorySeparatorChar -eq '\') {
        Assert-True `
            -Condition (-not (Test-ArtifactSigningFullyQualifiedPath `
                -Path 'C:relative\signtool.exe')) `
            -Message 'A drive-relative Windows path was accepted.'
        Assert-True `
            -Condition (-not (Test-ArtifactSigningFullyQualifiedPath `
                -Path '\root-relative\signtool.exe')) `
            -Message 'A root-relative Windows path was accepted.'
        Assert-True `
            -Condition (Test-ArtifactSigningFullyQualifiedPath `
                -Path 'C:\Windows\System32\signtool.exe') `
            -Message 'A drive-rooted Windows path was rejected.'
        Assert-True `
            -Condition (Test-ArtifactSigningFullyQualifiedPath `
                -Path '\\server\share\signtool.exe') `
            -Message 'A fully qualified UNC path was rejected.'
        Assert-True `
            -Condition (-not (Test-ArtifactSigningFullyQualifiedPath `
                -Path '\\?\C:\Windows\signtool.exe')) `
            -Message 'A Windows device path was accepted.'
    }

    $gitApplication = Get-ArtifactSigningApplicationPath -Name 'git'
    Assert-True `
        -Condition (
            $gitApplication -is [string] -and
            (Test-Path -LiteralPath $gitApplication -PathType Leaf)) `
        -Message 'The build application resolver did not return one file.'
    Assert-Throws -Action {
        Get-ArtifactSigningApplicationPath -Name 'git;invalid' | Out-Null
    } -Message 'An invalid build application name was accepted.'

    [IO.File]::AppendAllText(
        (Join-Path $testRoot 'Gateway/ArtifactSigning.Gateway.exe'),
        'tamper')
    Assert-Throws -Action {
        Read-ArtifactSigningReleaseInventory `
            -PackageRoot $testRoot `
            -ExpectedInventorySha256 $digest | Out-Null
    } -Message 'A tampered package file was accepted.'

    [IO.File]::WriteAllText(
        (Join-Path $testRoot 'Gateway/ArtifactSigning.Gateway.exe'),
        'gateway')
    $duplicateDeployment = [string]::Join(
        "`n",
        $deployment + 'GatewayListenPort=9443') + "`n"
    [IO.File]::WriteAllText(
        (Join-Path $testRoot 'deployment.txt'),
        $duplicateDeployment,
        [Text.Encoding]::ASCII)
    Assert-Throws -Action {
        Read-ArtifactSigningDeployment `
            -Path (Join-Path $testRoot 'deployment.txt') | Out-Null
    } -Message 'A duplicate deployment key was accepted.'

    $nestedPayload = Join-Path $testRoot 'Gateway/nested/extra.dll'
    [IO.Directory]::CreateDirectory(
        (Split-Path -Parent $nestedPayload)) | Out-Null
    [IO.File]::WriteAllText($nestedPayload, 'nested')
    Assert-Throws -Action {
        & (Join-Path $installerRoot `
            'New-ArtifactSigningReleaseInventory.ps1') `
            -PackageRoot $testRoot | Out-Null
    } -Message 'A nested release payload path was accepted.'
    Remove-Item -LiteralPath (Split-Path -Parent $nestedPayload) `
        -Recurse -Force

    [IO.File]::WriteAllText(
        (Join-Path $testRoot 'unexpected.bin'),
        'unexpected')
    Assert-Throws -Action {
        & (Join-Path $installerRoot `
            'New-ArtifactSigningReleaseInventory.ps1') `
            -PackageRoot $testRoot | Out-Null
    } -Message 'An unsupported release path was accepted.'
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

Write-Output 'INSTALLER_SOURCE_TESTS_OK'
