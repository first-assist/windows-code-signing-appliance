# Development and testing

## Toolchain

The repository targets .NET 10 and uses the SDK pinned by `global.json`. Install:

- Git;
- the pinned .NET SDK;
- PowerShell 7 for composition and release scripts;
- Python 3 for the deterministic release-archive helper; and
- on Windows acceptance hosts, the reviewed x64 Windows SDK SignTool.

Do not substitute a newer local SDK or SignTool silently. A tool change is a reviewed dependency or
deployment-policy change and must pass the relevant matrix.

## Repository build

Run from the repository root:

```bash
dotnet restore ArtifactSigning.sln --locked-mode \
  -p:NuGetAudit=true -p:NuGetAuditMode=all -p:NuGetAuditLevel=low
dotnet format ArtifactSigning.sln --verify-no-changes --no-restore
dotnet build ArtifactSigning.sln --configuration Release --no-restore
dotnet test ArtifactSigning.sln --configuration Release --no-build --no-restore
dotnet list ArtifactSigning.sln package --vulnerable --include-transitive
```

Also run the installer source contracts with PowerShell 7:

```powershell
./tests/installer/Installer.Source.Tests.ps1
```

On Windows, repeat that test under Windows PowerShell 5.1 because the installed scripts support
that host. CI performs both variants.

## Test layers

### Cross-platform unit and integration tests

The ordinary solution suite covers:

- canonical protocol JSON, digests, CMS signatures, tar archives, and state transitions;
- profile contracts, static package identity, and the synthetic profile;
- Gateway authorization, API, storage, handoff, startup reconciliation, and audit behavior;
- Worker configuration, notifications, state, signing coordination, output publication, and audit;
- CLI configuration, TLS/API behavior, archive validation, and receipt verification;
- timestamp relay configuration, media types, bounds, upstream behavior, and readiness; and
- Windows policy parsing and adapters that can be exercised without a live signing key.

All test certificates are generated and disposable. Never make a test depend on a retained
certificate, external signing account, private environment address, production timestamp endpoint,
or live infrastructure.

### Native Windows generated-key matrix

Set the acceptance variables only on a disposable Windows host with the intended SignTool:

```powershell
$env:ARTIFACT_SIGNING_RUN_GENERATED_MATRIX = '1'
$env:ARTIFACT_SIGNING_TEST_SIGNTOOL = 'C:\Program Files (x86)\Windows Kits\10\bin\<version>\x64\signtool.exe'
dotnet test .\tests\ArtifactSigning.Acceptance.Tests\ArtifactSigning.Acceptance.Tests.csproj `
  --configuration Release
```

The matrix generates a temporary certificate and loopback RFC 3161 authority. It must never select
or import a retained certificate. Review the test source and exact SignTool hash before enabling
the gate.

### Disposable installation acceptance

Source tests do not prove the native Windows installer, service controller, CNG provider, ACL,
firewall, Event Log, Windows Time, reboot, or rollback behavior. A release candidate therefore
requires a new disposable Windows machine or VM matching the production target.

Create a clean pre-key recovery point, install only generated test identities, and test:

1. a clean install and installed verifier;
2. Gateway and Worker key-permission separation;
3. exact services, dependencies, event sources, ACLs, firewall, time, and SignTool state;
4. profile discovery and complete signing through the real services;
5. separate service restarts and cold reboot;
6. release update and complete-generation rollback;
7. timestamp/revocation/time failure;
8. archive, database, configuration, profile lock, filesystem, and ACL tampering;
9. interruption during signing and quarantine behavior; and
10. destruction of the disposable machine and generated private-key state.

The automation used to control a particular hypervisor or cloud belongs outside this repository.
The acceptance contract is provider-independent and should drive that private automation.

See [disposable Windows test lab](disposable-windows-test-lab.md) for the safety boundary and
[Windows installation and hardening](windows-installation-hardening.md) for installed checks.

## Profile testing

Production profile source lives in its consumer repository. It should reference the exact reviewed
profile ABI and run its own formatting, warnings-denied build, tests, dependency audit, and secret
scan. Required adversarial cases include:

- missing, duplicate, extra, renamed, oversized, or unstable artifacts;
- pre-signed or malformed executable input;
- alternate data streams, links, reparse points, traversal, and archive ambiguity;
- malformed or noncanonical manifests and version fields;
- wrong signer, timestamp, hash, role, or policy alias;
- partial signing and mixed signed/unsigned output;
- nondeterministic finalization; and
- compatibility vectors for every retained profile version.

The synthetic `tests/ArtifactSigning.TestProfile` and
`tests/ArtifactSigning.TestProfile.Tests` projects are reference material for those patterns. They
must not acquire organization-specific rules or release credentials.

## Release publish checks

CI publishes each distributable with locked dependencies:

- Gateway: self-contained `win-x64`;
- Worker: self-contained `win-x64`;
- CLI: self-contained `win-x64` and `linux-x64`;
- timestamp relay: self-contained `linux-x64`; and
- disposable lab support: self-contained `win-x64`.

Release composition adds the reviewed profile package set and configuration templates. A plain
`dotnet publish` output is not an installable or authorized appliance release.

## Dependency and secret review

Dependencies are centrally pinned in `Directory.Packages.props` and lock files are committed. Use
locked restore and review every dependency update. The required audit level includes transitive
packages and low-severity advisories so the decision is visible rather than silently filtered.

Run a full-history secret scanner before publishing a fresh history and a current-tree scan on every
change. A clean scanner result does not authorize committing a certificate or credential. Never add
real private keys, PFX/P12 files, API tokens, client secrets, password files, provider credentials,
certificate contents, or live protected configuration.

## Versioning

Gateway, Worker, CLI, protocol, profile ABI, Windows adapter, timestamp relay, installer, test
profile, and tools have independent semantic versions. If behavior or shipped bytes change, update
the affected component version in the same commit. Never redistribute changed bytes under an old
version.

Profile package versions describe exact package bytes. Profile versions describe accepted input,
output meaning, and security behavior. A package-only version change cannot reinterpret an existing
profile version.

## Documentation checks

Before merging:

- verify every relative Markdown link resolves;
- scan tracked content for private project names, addresses, hostnames, VM identifiers, and evidence;
- ensure examples use reserved or clearly labeled placeholder values;
- ensure public instructions do not depend on a particular hypervisor; and
- keep internal operations records, live inventories, acceptance evidence, and AI/session plans in
  a separate private location.

## No live mutation from source work

Building, testing, or reviewing this repository does not authorize creating, importing, exporting,
rotating, or using a live key; changing a live VM; deploying a release; editing a firewall; or
publishing a repository. Each is a separate operator-approved acceptance step.
