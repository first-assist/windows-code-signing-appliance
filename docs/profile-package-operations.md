# Profile package operations

## Offline composition

The operator receives reviewed package directories through an offline release process. Each input
must be a direct single-link regular `profile-package.txt` and the named direct single-link assembly.
The canonical manifest has five fixed ASCII/LF `Name=Value` lines followed by one or more
`Profile` lines:

```text
Format=ArtifactSigningProfilePackageV1
PackageId=<safe-identifier>
PackageVersion=<canonical-semver>
AssemblyFile=<safe-leaf-dll-name>
AssemblySha256=<lowercase-sha256>
Profile=<profile-id>|<positive-version>|<static-singleton-type-name>
```

`eng/ProfileComposition/Compose-ProfileSet.ps1` is the only composition pattern. It validates every
manifest and exact assembly, rejects extra package entries and duplicate package/profile identities,
copies the already hashed assembly bytes into its temporary composition root, computes
descriptor/package/profile/package-set digests, then emits:

- `InstalledProfileSet.g.cs`, static registrations linked into Gateway, Worker, and CLI;
- `ArtifactSigning.ProfileComposition.props`, exact hash-pinned assembly references; and
- `profile-set.lock`, canonical package-set inventory and digest.

The composer never installs a package, contacts a feed, changes an appliance, or loads a package
at runtime. Review generated source and lock alongside the package inputs. The profile set must be
nonempty, deterministic, and identical for Gateway, Worker, and CLI.

## Sealed appliance release

Pass one or more canonical package manifests to `Build-ArtifactSigningRelease.ps1`. The builder runs
the composer in a new temporary directory, compiles the generated registrations and the exact copied
assembly bytes into each single-file executable, and carries the canonical lock in the protected
release inventory. The source project is not rebuilt in place of the reviewed package DLL.
Gateway configuration V2 and Worker configuration V2/V3 contain `ProfileSetSha256`; startup compares it to the compiled
set. The Gateway profile discovery response includes the matching package-set/package binding, and
the CLI rejects a mismatch before submission.

The installer validates the closed inventory, direct paths, exact ACLs, Gateway V2/Worker V2 or V3
configuration, and component/profile-set digests before enabling services. It never accepts a profile through HTTPS,
configuration substitution, a service command line, a package directory, or an assembly load context.

## Update, rollback, and history

A package addition, removal, byte change, or package-set change is a full appliance release.

1. Close Gateway intake and terminally resolve or quarantine nonterminal requests.
2. Retain external Gateway/Worker audit heads and the current profile-set lock.
3. Build and independently authorize a complete new release inventory.
4. Stage and install it with the normal offline update process; start Worker before Gateway.
5. Require installer verification, exact discovery binding, readiness/audit continuity, and the
   relevant disposable generated-key signing matrix before reopening intake.

Rollback restores the entire prior service/configuration/profile-set generation; it never changes
request state, keys, or receipt meaning. Retain historical package manifests, package assembly
hashes, package-set locks, appliance inventories, and matching CLI releases for receipt verification.
If package evidence is missing or inconsistent, fail closed and do not sign or reinterpret old output.
