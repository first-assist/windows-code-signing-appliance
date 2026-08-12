[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string] $ExpectedReleaseHash,

    [Parameter()]
    [ValidateSet('Install', 'Update')]
    [string] $Mode = 'Install'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ArtifactSigning.Installer.ps1')

$phase = 'HostValidation'
try {
Assert-ArtifactSigningInstallerHost
$paths = Get-ArtifactSigningInstallerPaths
$phase = 'ReleaseValidation'
$packageRoot = $paths.StagingRoot
$inventory = Read-ArtifactSigningReleaseInventory `
    -PackageRoot $packageRoot `
    -ExpectedInventorySha256 $ExpectedReleaseHash
$phase = 'DeploymentValidation'
$deployment = Read-ArtifactSigningDeployment `
    -Path (Join-Path $packageRoot 'deployment.txt')
Test-ArtifactSigningProfileSetLock `
    -Path (Join-Path $packageRoot 'profiles\profile-set.lock') `
    -ExpectedProfileSetSha256 $deployment.Values.ProfileSetSha256

$phase = 'ExistingStateValidation'
$existingServices = @(
    Get-Service -Name ArtifactSigningGateway,ArtifactSigningWorker `
        -ErrorAction SilentlyContinue
)
if ($Mode -ceq 'Install' -and
    ($existingServices.Count -ne 0 -or
        (Test-Path -LiteralPath $paths.InstallRoot))) {
    throw 'A divergent or existing installation is present.'
}
if ($Mode -ceq 'Update' -and
    ($existingServices.Count -ne 2 -or
        -not (Test-Path -LiteralPath $paths.InstallRoot))) {
    throw 'An accepted existing installation is required for update.'
}

    if ($Mode -ceq 'Update') {
        $phase = 'UpdatePreparation'
        Test-ArtifactSigningControlAcls -Paths $paths
        Test-ArtifactSigningInstalledVerifierExecutionTrust -Paths $paths
        Test-ArtifactSigningInstalledPayload -Paths $paths
        $existingDeployment = Read-ArtifactSigningReviewedRollbackDeployment `
            -Path $paths.InstalledDeployment
        Test-ArtifactSigningInstalledProfileSetEvidence `
            -Paths $paths -Deployment $existingDeployment
        $rollbackNext = "$($paths.RollbackRoot).next"
        if (Test-Path -LiteralPath $paths.RollbackRoot) {
            throw 'A protected rollback generation already exists.'
        }
        if (Test-Path -LiteralPath $rollbackNext) {
            Assert-ArtifactSigningDirectPath `
                -Path $rollbackNext -Directory $true
            foreach ($item in Get-ChildItem -LiteralPath $rollbackNext `
                -Recurse -Force) {
                $null = Get-ArtifactSigningRelativePath `
                    -Root $rollbackNext -Path $item.FullName
                Assert-ArtifactSigningDirectPath `
                    -Path $item.FullName -Directory $item.PSIsContainer
            }
            Start-ArtifactSigningServices
        }
        & (Join-Path $paths.InstallerRoot `
            'verify-artifact-signing-service.ps1')
        if (Test-Path -LiteralPath $rollbackNext) {
            Remove-ArtifactSigningDirectTree -Path $rollbackNext
        }
        [IO.Directory]::CreateDirectory($rollbackNext) | Out-Null
        $builtIn = Get-ArtifactSigningBuiltInSids
        $rollbackAdministrators = @(
            $builtIn.System,
            $builtIn.Administrators)
        Set-ArtifactSigningExactAcl -Path $rollbackNext `
            -FullControl $rollbackAdministrators `
            -ReadAndExecute @() -Directory $true
        Stop-ArtifactSigningServices
        Copy-Item -LiteralPath $paths.InstallRoot `
            -Destination (Join-Path $rollbackNext 'ArtifactSigning') `
            -Recurse
        foreach ($controlFile in @(
                $paths.InstalledInventory,
                $paths.InstalledDeployment,
                $paths.InstalledReleaseDigest,
                $paths.InstalledProfileSetLock)) {
            Copy-Item -LiteralPath $controlFile `
                -Destination $rollbackNext
        }
        Get-ChildItem -LiteralPath $rollbackNext `
            -Directory -Recurse -Force |
            ForEach-Object {
                Set-ArtifactSigningExactAcl -Path $_.FullName `
                    -FullControl $rollbackAdministrators `
                    -ReadAndExecute @() -Directory $true
            }
        Get-ChildItem -LiteralPath $rollbackNext `
            -File -Recurse -Force |
            ForEach-Object {
                Set-ArtifactSigningExactAcl -Path $_.FullName `
                    -FullControl $rollbackAdministrators `
                    -ReadAndExecute @() -Directory $false
            }
        $failedUpdateName = "ArtifactSigning.failed-$(`
            [DateTimeOffset]::UtcNow.ToString(
                'yyyyMMddHHmmss',
                [Globalization.CultureInfo]::InvariantCulture))"
        $failedUpdatePath = Join-Path `
            ([IO.Directory]::GetParent($paths.InstallRoot).FullName) `
            $failedUpdateName
        if (Test-Path -LiteralPath $failedUpdatePath) {
            throw 'The failed-update retention path already exists.'
        }
        $rollbackNextPaths = [pscustomobject]@{
            InstallRoot = Join-Path $rollbackNext 'ArtifactSigning'
            InstallerRoot = Join-Path `
                (Join-Path $rollbackNext 'ArtifactSigning') 'Installer'
            ControlRoot = $rollbackNext
            InstalledInventory = Join-Path $rollbackNext `
                'installed-inventory.txt'
            InstalledDeployment = Join-Path $rollbackNext `
                'installed-deployment.txt'
            InstalledReleaseDigest = Join-Path $rollbackNext `
                'installed-release.sha256'
            InstalledProfileSetLock = Join-Path $rollbackNext `
                'installed-profile-set.lock'
        }
        Test-ArtifactSigningControlAcls -Paths $rollbackNextPaths
        Test-ArtifactSigningInstalledVerifierExecutionTrust `
            -Paths $rollbackNextPaths
        Test-ArtifactSigningInstalledPayload -Paths $rollbackNextPaths
        $rollbackDeployment = Read-ArtifactSigningReviewedRollbackDeployment `
            -Path $rollbackNextPaths.InstalledDeployment
        Test-ArtifactSigningInstalledProfileSetEvidence `
            -Paths $rollbackNextPaths -Deployment $rollbackDeployment
        Write-ArtifactSigningRollbackState `
            -RollbackRoot $rollbackNext `
            -ExpectedState Absent -NewState Prepared `
            -FailedUpdateName $failedUpdateName `
            -ExpectedDisposition None -NewDisposition Pending
        Move-Item -LiteralPath $rollbackNext `
            -Destination $paths.RollbackRoot
        $committedRollback = Read-ArtifactSigningRollbackState `
            -RollbackRoot $paths.RollbackRoot
        if ($committedRollback.State -cne 'Prepared' -or
            $committedRollback.FailedUpdateName -cne $failedUpdateName -or
            $committedRollback.FailedUpdateDisposition -cne 'Pending') {
            throw 'The protected rollback generation was not committed.'
        }
        Remove-ArtifactSigningAzureArcIdentityAccess
        Remove-ArtifactSigningServiceDefinitions
        Remove-Item -LiteralPath $paths.InstallRoot -Recurse -Force
    }

    $phase = 'PayloadCopy'
    Copy-ArtifactSigningReleasePayload `
        -PackageRoot $packageRoot `
        -Paths $paths `
        -Inventory $inventory
    $phase = 'ServiceDefinitions'
    Install-ArtifactSigningServiceDefinitions `
        -Paths $paths -Deployment $deployment
    $phase = 'ServiceIdentity'
    $gatewaySid = Get-ArtifactSigningServiceSid `
        -ServiceName ArtifactSigningGateway
    $workerSid = Get-ArtifactSigningServiceSid `
        -ServiceName ArtifactSigningWorker
    $phase = 'AzureArcIdentity'
    Set-ArtifactSigningAzureArcIdentityAccess `
        -Deployment $deployment `
        -GatewaySid $gatewaySid `
        -WorkerSid $workerSid
    $phase = 'MicrosoftClientToolsValidation'
    Test-ArtifactSigningMicrosoftArtifactSigningClientTools `
        -Directory (Join-Path $paths.WorkerRoot `
            'MicrosoftArtifactSigningClient') `
        -Deployment $deployment
    $phase = 'ConfigurationExpansion'
    Expand-ArtifactSigningConfigurationTemplates `
        -PackageRoot $packageRoot `
        -Paths $paths `
        -Deployment $deployment `
        -GatewaySid $gatewaySid `
        -WorkerSid $workerSid
    $phase = 'InstallationAcl'
    Set-ArtifactSigningInstallationAcls `
        -Paths $paths `
        -GatewaySid $gatewaySid `
        -WorkerSid $workerSid
    $phase = 'StateDirectories'
    New-ArtifactSigningStateDirectories `
        -Paths $paths `
        -GatewaySid $gatewaySid `
        -WorkerSid $workerSid
    $phase = 'SignToolValidation'
    Test-ArtifactSigningSignTool -Deployment $deployment
    $phase = 'ComponentVersionValidation'
    Test-ArtifactSigningComponentVersions `
        -Paths $paths -Deployment $deployment
    $phase = 'KeyAcl'
    Set-ArtifactSigningKeyAcls `
        -Deployment $deployment `
        -GatewaySid $gatewaySid `
        -WorkerSid $workerSid
    $phase = 'EventSources'
    Register-ArtifactSigningEventSources
    $phase = 'FirewallPolicy'
    Set-ArtifactSigningFirewallPolicy `
        -Paths $paths `
        -Deployment $deployment
    $phase = 'TimePolicy'
    Set-ArtifactSigningTimePolicy -Deployment $deployment
    $phase = 'ControlState'
    Write-ArtifactSigningInstalledControlState `
        -Paths $paths `
        -PackageRoot $packageRoot `
        -ExpectedInventorySha256 $ExpectedReleaseHash `
        -Deployment $deployment
    $phase = 'ServiceStart'
    Start-ArtifactSigningServices
    $phase = 'AuditEvent'
    Write-ArtifactSigningInstallerEvent `
        -EntryType Information -EventId 1000 `
        -ResultCode INSTALL_OK
    $phase = 'StagingCleanup'
    Remove-Item -LiteralPath $packageRoot -Recurse -Force
}
catch {
    $failedPhase = $phase
    if ($failedPhase -ceq 'ServiceDefinitions' -and
        [string]$_.Exception.Message -cmatch (
            '^ArtifactSigningServiceDefinitionFailed:' +
            '(ToolValidation|WorkerCreate|WorkerIdentity|WorkerStartMode|' +
            'WorkerSidType|WorkerRecoveryActions|WorkerRecoveryFlag|' +
            'GatewayCreate|GatewayIdentity|GatewayStartMode|' +
            'GatewaySidType|GatewayRecoveryActions|GatewayRecoveryFlag)$')) {
        $failedPhase = "ServiceDefinitions$($Matches[1])"
    }
    if ($failedPhase -ceq 'InstallationAcl' -and
        [string]$_.Exception.Message -cmatch (
            '^ArtifactSigningInstallationAclFailed:' +
            '(InstallRoot|GatewayRoot|WorkerRoot|InstallerRoot|' +
            'GatewayFiles|WorkerFiles|InstallerFiles)$')) {
        $failedPhase = "InstallationAcl$($Matches[1])"
    }
    if ($failedPhase -ceq 'KeyAcl' -and
        [string]$_.Exception.Message -cmatch (
            '^ArtifactSigningKeyAclFailed:' +
            '((?:GatewayTls|Receipt|Authenticode)(?:Resolution|' +
            'CertificateSelection|PrivateKeyOpen|PrivateKeyPolicy|' +
            'PrivateKeyPath)|Distinctness|GatewayTlsWrite|' +
            'ReceiptWrite|AuthenticodeWrite)$')) {
        $failedPhase = "KeyAcl$($Matches[1])"
    }
    if ($failedPhase -ceq 'EventSources' -and
        [string]$_.Exception.Message -cmatch
            '^ArtifactSigningEventSourceFailed:(Gateway|Worker|Installer)$') {
        $failedPhase = "EventSources$($Matches[1])"
    }
    if ($failedPhase -ceq 'FirewallPolicy' -and
        [string]$_.Exception.Message -cmatch (
            '^ArtifactSigningFirewallPolicyFailed:' +
            '(Profiles|RuleSet|GatewayIn|WorkerTimestamp|' +
            'WorkerReadiness|WorkerMicrosoft|WorkerHimdsLoopback|' +
            'WorkerMicrosoftCertificateStatus|' +
            'WorkerMicrosoftCertificateStatusKeywords|' +
            'SignToolHimdsLoopback|ArcHimds|ArcProxy|' +
            'DnsUdp|DnsTcp|Time|GatewayRevocation|' +
            'WorkerRevocation)$')) {
        $failedPhase = "FirewallPolicy$($Matches[1])"
    }
    Write-ArtifactSigningInstallerEvent `
        -EntryType Error -EventId 1001 `
        -ResultCode INSTALL_FAILED
    if ($Mode -ceq 'Install') {
        $cleanupFailed = $false
        try {
            Remove-ArtifactSigningFirewallPolicy
        }
        catch {
            $cleanupFailed = $true
        }
        try {
            Remove-ArtifactSigningAzureArcIdentityAccess
        }
        catch {
            $cleanupFailed = $true
        }
        try {
            Remove-ArtifactSigningServiceDefinitions
        }
        catch {
            $cleanupFailed = $true
        }
        if ($cleanupFailed) {
            throw 'ArtifactSigningApplianceInstallFailed:FailureCleanup'
        }
    }
    throw "ArtifactSigningApplianceInstallFailed:$failedPhase"
}
