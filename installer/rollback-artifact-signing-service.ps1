[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ArtifactSigning.Installer.ps1')

Assert-ArtifactSigningInstallerHost
$paths = Get-ArtifactSigningInstallerPaths
$transaction = Read-ArtifactSigningRollbackState `
    -RollbackRoot $paths.RollbackRoot
$rollbackInstallation = Join-Path $paths.RollbackRoot 'ArtifactSigning'
$failedUpdate = Join-Path `
    ([IO.Directory]::GetParent($paths.InstallRoot).FullName) `
    $transaction.FailedUpdateName
if (Test-Path -LiteralPath $failedUpdate) {
    Assert-ArtifactSigningDirectPath -Path $failedUpdate -Directory $true
}
Test-ArtifactSigningFailedUpdateDisposition `
    -Transaction $transaction -FailedUpdatePath $failedUpdate
$priorInstallation = if ($transaction.State -ceq 'Prepared') {
    $rollbackInstallation
}
elseif ($transaction.State -ceq 'CurrentMoved' -and
    (Test-Path -LiteralPath $rollbackInstallation)) {
    $rollbackInstallation
}
else {
    $paths.InstallRoot
}
Assert-ArtifactSigningDirectPath `
    -Path $priorInstallation -Directory $true
$rollbackPaths = [pscustomobject]@{
    InstallRoot = $priorInstallation
    InstallerRoot = Join-Path $priorInstallation 'Installer'
    ControlRoot = $paths.RollbackRoot
    InstalledInventory = Join-Path $paths.RollbackRoot `
        'installed-inventory.txt'
    InstalledDeployment = Join-Path $paths.RollbackRoot `
        'installed-deployment.txt'
    InstalledReleaseDigest = Join-Path $paths.RollbackRoot `
        'installed-release.sha256'
    InstalledProfileSetLock = Join-Path $paths.RollbackRoot `
        'installed-profile-set.lock'
}
Test-ArtifactSigningControlAcls -Paths $rollbackPaths
Test-ArtifactSigningInstalledVerifierExecutionTrust -Paths $rollbackPaths
Test-ArtifactSigningInstalledPayload -Paths $rollbackPaths
. (Join-Path $rollbackPaths.InstallerRoot `
    'ArtifactSigning.Installer.ps1')
$priorDeployment = Read-ArtifactSigningDeployment `
    -Path $rollbackPaths.InstalledDeployment
Test-ArtifactSigningInstalledProfileSetEvidence `
    -Paths $rollbackPaths -Deployment $priorDeployment
if (-not $PSCmdlet.ShouldProcess(
        $paths.InstallRoot,
        'Replace the current service bytes and configuration with the protected prior generation')) {
    return
}

if ($transaction.State -cne 'Verified') {
    Stop-ArtifactSigningServices
    Remove-ArtifactSigningFirewallPolicy
    Remove-ArtifactSigningAzureArcIdentityAccess
    Remove-ArtifactSigningServiceDefinitions
}

$transaction = Read-ArtifactSigningRollbackState `
    -RollbackRoot $paths.RollbackRoot
if ($transaction.State -ceq 'Prepared') {
    $transaction = Move-ArtifactSigningRollbackCurrentGeneration `
        -Paths $paths -FailedUpdatePath $failedUpdate `
        -Transaction $transaction
}

if ($transaction.State -ceq 'CurrentMoved') {
    $transaction = Move-ArtifactSigningRollbackPriorGeneration `
        -Paths $paths `
        -RollbackInstallation $rollbackInstallation `
        -FailedUpdatePath $failedUpdate `
        -Transaction $transaction
}

if ($transaction.State -ceq 'PriorMoved') {
    foreach ($name in @(
            'installed-inventory.txt',
            'installed-deployment.txt',
            'installed-release.sha256',
            'installed-profile-set.lock')) {
        $destination = Join-Path $paths.ControlRoot $name
        if (Test-Path -LiteralPath $destination) {
            Assert-ArtifactSigningDirectPath `
                -Path $destination -Directory $false
            $destinationFile = Get-Item `
                -LiteralPath $destination -Force
            if ($destinationFile.IsReadOnly) {
                $destinationFile.IsReadOnly = $false
            }
        }
        Copy-Item -LiteralPath (Join-Path $paths.RollbackRoot $name) `
            -Destination $destination -Force
        $restoredFile = Get-Item -LiteralPath $destination -Force
        if ($restoredFile.IsReadOnly) {
            $restoredFile.IsReadOnly = $false
        }
    }
    $builtIn = Get-ArtifactSigningBuiltInSids
    $rollbackAdministrators = @(
        $builtIn.System,
        $builtIn.Administrators)
    Set-ArtifactSigningExactAcl -Path $paths.ControlRoot `
        -FullControl $rollbackAdministrators `
        -ReadAndExecute @() -Directory $true
    foreach ($controlFile in @(
            $paths.InstalledInventory,
            $paths.InstalledDeployment,
            $paths.InstalledReleaseDigest,
            $paths.InstalledProfileSetLock)) {
        Set-ArtifactSigningExactAcl -Path $controlFile `
            -FullControl $rollbackAdministrators `
            -ReadAndExecute @() -Directory $false
    }
    Test-ArtifactSigningControlAcls -Paths $paths
    Write-ArtifactSigningRollbackState `
        -RollbackRoot $paths.RollbackRoot `
        -ExpectedState PriorMoved -NewState ControlRestored `
        -FailedUpdateName $transaction.FailedUpdateName `
        -ExpectedDisposition $transaction.FailedUpdateDisposition `
        -NewDisposition $transaction.FailedUpdateDisposition
    $transaction = Read-ArtifactSigningRollbackState `
        -RollbackRoot $paths.RollbackRoot
}

if ($transaction.State -ceq 'ControlRestored') {
    Stop-ArtifactSigningServices
    Remove-ArtifactSigningFirewallPolicy
    Remove-ArtifactSigningAzureArcIdentityAccess
    Remove-ArtifactSigningServiceDefinitions
    if ($priorDeployment.Values.InstallerVersion -ceq '0.3.2') {
        Install-ArtifactSigningServiceDefinitions -Paths $paths
    }
    else {
        Install-ArtifactSigningServiceDefinitions `
            -Paths $paths -Deployment $priorDeployment
    }
    $gatewaySid = Get-ArtifactSigningServiceSid `
        -ServiceName ArtifactSigningGateway
    $workerSid = Get-ArtifactSigningServiceSid `
        -ServiceName ArtifactSigningWorker
    Set-ArtifactSigningAzureArcIdentityAccess `
        -Deployment $priorDeployment `
        -GatewaySid $gatewaySid -WorkerSid $workerSid
    Test-ArtifactSigningMicrosoftArtifactSigningClientTools `
        -Directory (Join-Path $paths.WorkerRoot `
            'MicrosoftArtifactSigningClient') `
        -Deployment $priorDeployment
    Set-ArtifactSigningInstallationAcls `
        -Paths $paths -GatewaySid $gatewaySid -WorkerSid $workerSid
    Set-ArtifactSigningKeyAcls `
        -Deployment $priorDeployment `
        -GatewaySid $gatewaySid -WorkerSid $workerSid
    Set-ArtifactSigningFirewallPolicy `
        -Paths $paths -Deployment $priorDeployment
    Set-ArtifactSigningTimePolicy -Deployment $priorDeployment
    Register-ArtifactSigningEventSources
    Start-ArtifactSigningServices
    & (Join-Path $paths.InstallerRoot `
        'verify-artifact-signing-service.ps1')
    Write-ArtifactSigningRollbackState `
        -RollbackRoot $paths.RollbackRoot `
        -ExpectedState ControlRestored -NewState Verified `
        -FailedUpdateName $transaction.FailedUpdateName `
        -ExpectedDisposition $transaction.FailedUpdateDisposition `
        -NewDisposition $transaction.FailedUpdateDisposition
    $transaction = Read-ArtifactSigningRollbackState `
        -RollbackRoot $paths.RollbackRoot
}

if ($transaction.State -cne 'Verified') {
    throw 'The rollback transaction did not reach verification.'
}
Test-ArtifactSigningFailedUpdateDisposition `
    -Transaction $transaction -FailedUpdatePath $failedUpdate
& (Join-Path $paths.InstallerRoot `
    'verify-artifact-signing-service.ps1')
Remove-ArtifactSigningDirectTree -Path $paths.RollbackRoot
Write-ArtifactSigningInstallerEvent `
    -EntryType Information -EventId 1005 `
    -ResultCode ROLLBACK_OK

$failedUpdateResult = if (
    $transaction.FailedUpdateDisposition -ceq 'Retained') {
    $failedUpdate
}
else {
    'NONE'
}
Write-Output "ROLLBACK_OK_FAILED_UPDATE_RETAINED=$failedUpdateResult"
