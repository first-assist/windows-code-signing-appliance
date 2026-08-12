[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $GatewayConfigurationTemplate,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $WorkerConfigurationTemplate,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $Deployment,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string[]] $ProfilePackageManifest,

    [Parameter()]
    [string] $MicrosoftArtifactSigningClientToolsDirectory,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $OutputRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot '..'))
. (Join-Path $PSScriptRoot 'ArtifactSigning.Installer.ps1')
$output = [IO.Path]::GetFullPath($OutputRoot)
if (Test-Path -LiteralPath $output) {
    throw 'The release output path already exists.'
}
if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw 'Profile composition requires PowerShell 7.'
}
foreach ($source in @(
        $GatewayConfigurationTemplate,
        $WorkerConfigurationTemplate,
        $Deployment) + $ProfilePackageManifest) {
    $item = Get-Item -LiteralPath (
        [IO.Path]::GetFullPath($source)) -Force
    if ($item.PSIsContainer -or
        ($item.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'A release configuration input is not a direct file.'
    }
}

$git = Get-ArtifactSigningApplicationPath -Name 'git'
$status = & $git -C $repositoryRoot `
    status --porcelain=v1 --untracked-files=all
if ($LASTEXITCODE -ne 0 -or @($status).Count -ne 0) {
    throw 'A release must be built from a clean worktree.'
}
$commit = & $git -C $repositoryRoot rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or $commit -cnotmatch '^[0-9a-f]{40}$') {
    throw 'The release source commit is unavailable.'
}

$deploymentLines = [IO.File]::ReadAllLines(
    [IO.Path]::GetFullPath($Deployment),
    [Text.Encoding]::ASCII)
if ($deploymentLines -cnotcontains "SourceCommit=$commit") {
    throw 'The deployment policy is not bound to the clean source commit.'
}
$deploymentPolicy = Read-ArtifactSigningDeployment `
    -Path ([IO.Path]::GetFullPath($Deployment))
$microsoftClientToolsSource = $null
if ($deploymentPolicy.IsMicrosoftArtifactSigning) {
    if ([string]::IsNullOrEmpty(
            $MicrosoftArtifactSigningClientToolsDirectory)) {
        throw 'A Microsoft Artifact Signing deployment requires its pinned client tools.'
    }
    $microsoftClientToolsSource = [IO.Path]::GetFullPath(
        $MicrosoftArtifactSigningClientToolsDirectory)
    Test-ArtifactSigningMicrosoftArtifactSigningClientTools `
        -Directory $microsoftClientToolsSource `
        -Deployment $deploymentPolicy `
        -RequireInstalledRuntime $false
}
elseif (-not [string]::IsNullOrEmpty(
        $MicrosoftArtifactSigningClientToolsDirectory)) {
    throw 'A Local Machine deployment cannot package Microsoft Artifact Signing client tools.'
}
$compositionRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'artifact-signing-profile-composition-' + [Guid]::NewGuid().ToString('N'))
$profileComposer = Join-Path $repositoryRoot `
    'eng\ProfileComposition\Compose-ProfileSet.ps1'
if (-not (Test-Path -LiteralPath $profileComposer)) {
    throw 'The offline profile composer is unavailable.'
}
[IO.Directory]::CreateDirectory($compositionRoot) | Out-Null
try {
    & $profileComposer `
        -Manifest $ProfilePackageManifest `
        -OutputDirectory $compositionRoot
    if ($LASTEXITCODE -ne 0) {
        throw 'Offline profile composition failed.'
    }

    $profileSetLock = Join-Path $compositionRoot 'profile-set.lock'
    Test-ArtifactSigningProfileSetLock `
        -Path $profileSetLock `
        -ExpectedProfileSetSha256 $deploymentPolicy.Values.ProfileSetSha256

[IO.Directory]::CreateDirectory($output) | Out-Null
foreach ($directory in @(
        'Gateway',
        'Worker',
        'config',
        'installer',
        'profiles')) {
    [IO.Directory]::CreateDirectory(
        (Join-Path $output $directory)) | Out-Null
}

$dotnet = Get-ArtifactSigningApplicationPath -Name 'dotnet'
foreach ($component in @(
        @{
            Project = Join-Path $repositoryRoot `
                'src\ArtifactSigning.Gateway\ArtifactSigning.Gateway.csproj'
            Output = Join-Path $output 'Gateway'
        },
        @{
            Project = Join-Path $repositoryRoot `
                'src\ArtifactSigning.Worker\ArtifactSigning.Worker.csproj'
            Output = Join-Path $output 'Worker'
        },
        @{
            Project = Join-Path $repositoryRoot `
                'src\ArtifactSigning.Cli\ArtifactSigning.Cli.csproj'
            Output = Join-Path $output 'installer'
        })) {
    & $dotnet publish $component.Project `
        --configuration Release `
        --runtime win-x64 `
        --self-contained true `
        --output $component.Output `
        -p:RestoreLockedMode=true `
        -p:PublishSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:PublishTrimmed=false `
        -p:PublishReadyToRun=false `
        "-p:ArtifactSigningProfileCompositionProps=$(Join-Path $compositionRoot 'ArtifactSigning.ProfileComposition.props')"
    if ($LASTEXITCODE -ne 0) {
        throw 'A Windows release component publish failed.'
    }
}
Get-ChildItem -LiteralPath $output -Filter '*.pdb' -File -Recurse |
    Remove-Item -Force
Get-ChildItem -LiteralPath $output `
    -Filter 'packages.lock.json' -File -Recurse |
    Remove-Item -Force
foreach ($generated in @(
        (Join-Path $output 'Gateway\web.config'),
        (Join-Path $output `
            'Gateway\ArtifactSigning.Gateway.staticwebassets.endpoints.json'))) {
    if (Test-Path -LiteralPath $generated) {
        Remove-Item -LiteralPath $generated -Force
    }
}

[IO.File]::Copy(
    [IO.Path]::GetFullPath($GatewayConfigurationTemplate),
    (Join-Path $output 'config\gateway.template.json'))
[IO.File]::Copy(
    [IO.Path]::GetFullPath($WorkerConfigurationTemplate),
    (Join-Path $output 'config\worker.template.json'))
[IO.File]::Copy(
    [IO.Path]::GetFullPath($Deployment),
    (Join-Path $output 'deployment.txt'))
[IO.File]::Copy(
    $profileSetLock,
    (Join-Path $output 'profiles\profile-set.lock'))
Get-ChildItem -LiteralPath $PSScriptRoot `
    -Filter '*.ps1' -File |
    ForEach-Object {
        [IO.File]::Copy(
            $_.FullName,
            (Join-Path (Join-Path $output 'installer') $_.Name))
    }
if ($deploymentPolicy.IsMicrosoftArtifactSigning) {
    $clientToolsOutput = Join-Path $output `
        'Worker\MicrosoftArtifactSigningClient'
    [IO.Directory]::CreateDirectory($clientToolsOutput) | Out-Null
    foreach ($clientTool in @(
            Get-ChildItem -LiteralPath $microsoftClientToolsSource `
                -File -Force)) {
        [IO.File]::Copy(
            $clientTool.FullName,
            (Join-Path $clientToolsOutput $clientTool.Name))
    }
}

$inventoryDigest = & (Join-Path $PSScriptRoot `
    'New-ArtifactSigningReleaseInventory.ps1') `
    -PackageRoot $output
if ($LASTEXITCODE -ne 0 -or
    $inventoryDigest -cnotmatch '^[0-9a-f]{64}$') {
    throw 'The release inventory could not be produced.'
}

Write-Output "RELEASE_COMMIT=$commit"
Write-Output "RELEASE_INVENTORY_SHA256=$inventoryDigest"
}
finally {
    if (Test-Path -LiteralPath $compositionRoot) {
        Remove-Item -LiteralPath $compositionRoot -Recurse -Force
    }
}
