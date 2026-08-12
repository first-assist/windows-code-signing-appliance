[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ArtifactSigning.Installer.ps1')

$phase = 'HostValidation'
try {
    Assert-ArtifactSigningInstallerHost
    $paths = Get-ArtifactSigningInstallerPaths
    $phase = 'ControlAcls'
    Test-ArtifactSigningControlAcls -Paths $paths
    $phase = 'InstalledPayload'
    $expectedHash = [IO.File]::ReadAllText(
        $paths.InstalledReleaseDigest,
        [Text.Encoding]::ASCII).TrimEnd("`n")
    if (-not (Test-ArtifactSigningLowerSha256 -Value $expectedHash)) {
        throw 'The installed release identity is invalid.'
    }
    Test-ArtifactSigningInstalledPayload -Paths $paths
    $phase = 'DeploymentValidation'
    $deployment = Read-ArtifactSigningDeployment `
        -Path $paths.InstalledDeployment
    Test-ArtifactSigningInstalledProfileSetEvidence `
        -Paths $paths -Deployment $deployment
    $gatewaySid = Get-ArtifactSigningServiceSid `
        -ServiceName ArtifactSigningGateway
    $workerSid = Get-ArtifactSigningServiceSid `
        -ServiceName ArtifactSigningWorker
    $phase = 'ServiceDefinitions'
    Test-ArtifactSigningServiceDefinitions `
        -Paths $paths -Deployment $deployment
    $phase = 'AzureArcIdentity'
    Test-ArtifactSigningAzureArcIdentityAccess `
        -Deployment $deployment `
        -GatewaySid $gatewaySid `
        -WorkerSid $workerSid
    $phase = 'MicrosoftClientToolsValidation'
    Test-ArtifactSigningMicrosoftArtifactSigningClientTools `
        -Directory (Join-Path $paths.WorkerRoot `
            'MicrosoftArtifactSigningClient') `
        -Deployment $deployment
    $phase = 'InstallationAcls'
    Test-ArtifactSigningInstallationAcls `
        -Paths $paths `
        -GatewaySid $gatewaySid `
        -WorkerSid $workerSid
    $phase = 'StateDirectories'
    Test-ArtifactSigningStateDirectories `
        -Paths $paths `
        -GatewaySid $gatewaySid `
        -WorkerSid $workerSid
    $phase = 'KeyAcls'
    Test-ArtifactSigningKeyAcls `
        -Deployment $deployment `
        -GatewaySid $gatewaySid `
        -WorkerSid $workerSid
    $phase = 'SignToolValidation'
    Test-ArtifactSigningSignTool -Deployment $deployment
    $phase = 'ComponentVersionValidation'
    Test-ArtifactSigningComponentVersions `
        -Paths $paths -Deployment $deployment
    $phase = 'FirewallPolicy'
    Test-ArtifactSigningFirewallPolicy `
        -Paths $paths -Deployment $deployment
    $phase = 'TimePolicy'
    Test-ArtifactSigningTimePolicy -Deployment $deployment
    $phase = 'EventSources'
    Test-ArtifactSigningEventSources
    $phase = 'ServiceStatus'
    foreach ($name in @(
            'ArtifactSigningWorker',
            'ArtifactSigningGateway')) {
        if ((Get-Service -Name $name).Status -ne 'Running') {
            throw 'An Artifact Signing service is not running.'
        }
    }
    $phase = 'AuditEvent'
    Write-ArtifactSigningInstallerEvent `
        -EntryType Information -EventId 1002 `
        -ResultCode VERIFY_OK
}
catch {
    $failedPhase = $phase
    $controlAclFailurePhases = @{
        'ArtifactSigningControlAclFailed:Root' =
            'ControlAclsRoot'
        'ArtifactSigningControlAclFailed:RootDirectPath' =
            'ControlAclsRootDirectPath'
        'ArtifactSigningControlAclFailed:RootSecurityDescriptor' =
            'ControlAclsRootSecurityDescriptor'
        'ArtifactSigningControlAclFailed:RootOwnerOrProtection' =
            'ControlAclsRootOwnerOrProtection'
        'ArtifactSigningControlAclFailed:RootRules' =
            'ControlAclsRootRules'
        'ArtifactSigningControlAclFailed:Inventory' =
            'ControlAclsInventory'
        'ArtifactSigningControlAclFailed:Deployment' =
            'ControlAclsDeployment'
        'ArtifactSigningControlAclFailed:ReleaseDigest' =
            'ControlAclsReleaseDigest'
        'ArtifactSigningControlAclFailed:ProfileSetLock' =
            'ControlAclsProfileSetLock'
    }
    if ($failedPhase -ceq 'ControlAcls' -and
        $controlAclFailurePhases.ContainsKey(
            [string]$_.Exception.Message)) {
        $failedPhase = $controlAclFailurePhases[
            [string]$_.Exception.Message]
    }
    $serviceDefinitionFailurePhases = @{
        'ArtifactSigningServiceDefinitionValidationFailed:WorkerDependency' =
            'ServiceDefinitionsWorkerDependency'
        'ArtifactSigningServiceDefinitionValidationFailed:GatewayDependency' =
            'ServiceDefinitionsGatewayDependency'
        'ArtifactSigningServiceDefinitionValidationFailed:WorkerImagePath' =
            'ServiceDefinitionsWorkerImagePath'
        'ArtifactSigningServiceDefinitionValidationFailed:GatewayImagePath' =
            'ServiceDefinitionsGatewayImagePath'
    }
    if ($failedPhase -ceq 'ServiceDefinitions' -and
        $serviceDefinitionFailurePhases.ContainsKey(
            [string]$_.Exception.Message)) {
        $failedPhase = $serviceDefinitionFailurePhases[
            [string]$_.Exception.Message]
    }
    if ($failedPhase -ceq 'InstallationAcls' -and
        [string]$_.Exception.Message -cmatch (
            '^ArtifactSigningInstallationAclFailed:' +
            '(InstallRoot|GatewayRoot|WorkerRoot|InstallerRoot|' +
            'GatewayFiles|WorkerFiles|InstallerFiles)$')) {
        $failedPhase = "InstallationAcls$($Matches[1])"
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
        -EntryType Error -EventId 1003 `
        -ResultCode VERIFY_FAILED
    throw "ArtifactSigningApplianceVerifyFailed:$failedPhase"
}
