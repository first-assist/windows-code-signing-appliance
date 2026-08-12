[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $PackageRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = [IO.Path]::GetFullPath($PackageRoot)
$inventoryPath = Join-Path $root 'release-inventory.txt'
if (Test-Path -LiteralPath $inventoryPath) {
    Remove-Item -LiteralPath $inventoryPath -Force
}

$allowed = (
    '^Gateway/[A-Za-z0-9._-]+$|' +
    '^Worker/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$|' +
    '^config/(?:gateway|worker)\.template\.json$|' +
    '^installer/(?:[A-Za-z0-9._-]+\.ps1|artifact-signctl\.exe)$|' +
    '^profiles/profile-set\.lock$|' +
    '^deployment\.txt$')
$lines = @(
    Get-ChildItem -LiteralPath $root -File -Recurse -Force |
        ForEach-Object {
            if (($_.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'A package source file is a reparse point.'
            }
            $canonicalRoot = $root.TrimEnd(
                [IO.Path]::DirectorySeparatorChar,
                [IO.Path]::AltDirectorySeparatorChar)
            $prefix = "$canonicalRoot$(
                [IO.Path]::DirectorySeparatorChar)"
            if (-not $_.FullName.StartsWith(
                    $prefix,
                    [StringComparison]::OrdinalIgnoreCase)) {
                throw 'A package source file escapes its root.'
            }
            $relative = $_.FullName.Substring(
                $prefix.Length).Replace(
                    [IO.Path]::DirectorySeparatorChar,
                    '/')
            if ($relative -cnotmatch $allowed) {
                throw 'A package source contains an unsupported path.'
            }
            $digest = (
                Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
            ).Hash.ToLowerInvariant()
            "$digest $($_.Length) $relative"
        } |
        Sort-Object
)
if ($lines.Count -lt 5) {
    throw 'The package source is incomplete.'
}
[IO.File]::WriteAllText(
    $inventoryPath,
    ([string]::Join("`n", $lines) + "`n"),
    [Text.Encoding]::ASCII)
$inventoryDigest = (
    Get-FileHash -LiteralPath $inventoryPath -Algorithm SHA256
).Hash.ToLowerInvariant()

Write-Output $inventoryDigest
