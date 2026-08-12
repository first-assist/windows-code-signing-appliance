# Contributing

Contributions are welcome when they preserve the appliance's narrow security boundary. Start with
the [architecture](docs/architecture.md), [threat model](docs/threat-model.md), and relevant
component documentation before changing a contract or implementation.

## Project scope

Appropriate contributions improve the project-agnostic Authenticode appliance, protocol, static
profile ABI/composition, CLI, narrow timestamp relay, hardened installer, verification, tests, or
public documentation.

The following are intentionally out of scope:

- remote command execution or general arbitrary-file signing;
- client-selected executable paths, output paths, certificate selectors, timestamp URLs, signing
  options, or free-form profiles;
- runtime plugins, uploaded assemblies, package feeds, or dynamic profile loading;
- certificate lifecycle management, private-key export, build/deployment orchestration, or artifact
  hosting;
- consumer-specific production profiles or compatibility corpora; and
- hypervisor/cloud automation, live host inventory, internal plans, or environment evidence.

Keep consumer profiles in their owning repositories and provider-specific operations in private
infrastructure repositories.

## Development workflow

1. Create a focused branch from current `main`.
2. Keep the worktree clean of generated artifacts and environment configuration.
3. Update the affected component's semantic version when shipped behavior or bytes change.
4. Add tests for success, bounds, malformed input, and relevant fail-closed behavior.
5. Update public documentation when contracts or operator behavior change.
6. Run the gates in [development and testing](docs/development.md).
7. Review the complete diff for secrets, private names/addresses, paths, and unrelated changes.

Use nullable reference types, warnings as errors, analyzers, deterministic builds, central package
versions, and committed lock files. JSON contracts use PascalCase. Timestamps are UTC RFC 3339 with
whole seconds unless a protocol says otherwise. SHA-256 is canonical lowercase hexadecimal;
certificate thumbprints are uppercase hexadecimal.

## Security requirements

Never add, print, export, or test with a real private key, PFX, certificate credential, API token,
client credential, signing-provider secret, or protected production configuration. Signing tests
must generate a disposable test certificate.

Do not weaken these invariants:

- only Worker may use the Authenticode and receipt keys;
- Worker has no listener;
- SignTool is one absolute hash-pinned executable invoked directly without a shell;
- Gateway and Worker independently re-hash and revalidate;
- production requires mTLS, submitter signature, exact-digest approval, and distinct identities;
- profile code is compiled statically from an operator-reviewed package set;
- state, files, archives, concurrency, time, rates, and responses remain bounded; and
- timestamp, revocation, signer, audit, state, or restart uncertainty fails closed.

See [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## Required checks

```bash
dotnet restore ArtifactSigning.sln --locked-mode \
  -p:NuGetAudit=true -p:NuGetAuditMode=all -p:NuGetAuditLevel=low
dotnet format ArtifactSigning.sln --verify-no-changes --no-restore
dotnet build ArtifactSigning.sln --configuration Release --no-restore
dotnet test ArtifactSigning.sln --configuration Release --no-build --no-restore
dotnet list ArtifactSigning.sln package --vulnerable --include-transitive
```

Run `tests/installer/Installer.Source.Tests.ps1` under PowerShell 7 and Windows PowerShell 5.1. Run
the relevant native Windows generated-key, installer, restart, reboot, update, rollback, and failure
matrix for Windows or security-sensitive changes. CI is a baseline, not a substitute for required
native acceptance.

## Pull requests

Describe:

- the exact problem and security boundary affected;
- why the change remains within scope;
- component/profile version changes;
- tests and native matrices run;
- new failure behavior and safe result codes; and
- documentation and compatibility impact.

Do not include live infrastructure screenshots, VM names, addresses, configuration, logs, signing
evidence, or internal review plans. Redact sensitive environment details before attaching any
diagnostic.

By contributing, you agree that your contribution is licensed under the Apache License 2.0.
