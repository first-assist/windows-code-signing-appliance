# Profile authoring

Consumer teams own profile source in a separate repository. The generic appliance owns the
protocol, archive parser, authorization, durable state, signing adapter, installer, and package
composer; it does not contain consumer validation rules, compatibility data, release credentials,
or production profile packages.

A profile is security policy that executes inside the key-bearing Worker. Treat profile review like
signing-service code review, not ordinary configuration review.

## What a profile controls

A profile closes:

- allowed project identifiers and source repository identifiers;
- one profile identifier and positive profile version;
- the exact artifact roles, safe leaf filenames, kinds, and maximum sizes;
- the maximum complete request size;
- allowed installed signer and timestamp policy aliases;
- unsigned manifest, build-evidence, executable, version, and hash validation;
- deterministic final-manifest generation; and
- finalized signed-output validation.

A profile does not choose a certificate, timestamp URL, executable, directory, command argument, or
credential. It names only signer/timestamp policy aliases already installed in Worker configuration.
The client can select only the project/profile identity authorized in Gateway and Worker.

## Package constraints

One package contains:

- canonical `profile-package.txt`; and
- exactly one declared direct regular managed assembly.

There are no consumer dependency DLLs, native libraries, scripts, configuration files, certificate
files, credentials, or runtime package downloads. Build against the exact reviewed
`ArtifactSigning.Profiles` ABI used by the appliance release and only framework/host contract
dependencies available to that release.

The composer references the reviewed assembly at compile time and generates direct calls to each
declared type's public static `Instance` property. It never loads the package assembly dynamically.

## 1. Create the profile project

Use a .NET 10 class library in the consumer repository. Enable nullable reference types, warnings as
errors, analyzers, deterministic builds, central dependency pinning, and a committed lock file. For
local development, reference the exact reviewed `ArtifactSigning.Profiles` contract source or
approved package produced from the appliance release. Do not float to an arbitrary branch or
package version.

Keep the assembly self-contained from other consumer assemblies. The test-only project at
`tests/ArtifactSigning.TestProfile/ArtifactSigning.TestProfile.csproj` shows the expected project
shape; its project reference is for this repository's test build and is not a production supply
chain.

## 2. Define identity and descriptor

Implement `ISigningProfile` as a sealed type with a private constructor and a public static
singleton:

```csharp
using ArtifactSigning.Profiles;

namespace Example.Profile.Package;

public sealed class ExampleBundleV1 : ISigningProfile
{
    public static ExampleBundleV1 Instance { get; } = new();

    private static readonly SigningProfileDescriptor CompiledDescriptor = new(
        new SigningProfileIdentity("ExampleBundleV1", 1),
        allowedProjectIds: ["example-project"],
        allowedSourceRepositories: ["example/repository"],
        artifacts:
        [
            new SigningProfileArtifactDefinition(
                "Manifest",
                "release-manifest.json",
                SigningProfileArtifactKind.JsonManifest,
                64 * 1024),
            new SigningProfileArtifactDefinition(
                "Application",
                "ExampleApplication.exe",
                SigningProfileArtifactKind.PortableExecutable,
                32 * 1024 * 1024),
        ],
        allowedSignerPolicyIds: ["ProductionAuthenticodeV1"],
        allowedTimestampPolicyIds: ["PublicRfc3161V1"],
        maximumRequestBytes: 40 * 1024 * 1024);

    private ExampleBundleV1() { }

    public SigningProfileDescriptor Descriptor => CompiledDescriptor;

    // Implement all three ISigningProfile methods as described below.
}
```

The example illustrates descriptor construction only. It is not a complete or secure profile until
all validation/finalization methods and adversarial tests are implemented.

The descriptor permits one through 64 artifacts and requires exactly one
`JsonManifest`. Roles and filenames are unique ordinal strings. A filename is one safe leaf token,
never a path. Available kinds are `JsonManifest`, `JsonBuildEvidence`, and `PortableExecutable`.

Policy aliases are stable operator-reviewed identifiers. The same aliases must exist in Worker
`SigningPolicies`, and Gateway/Worker authorization must name the same project/profile/version.

## 3. Validate the unsigned bundle

Implement:

```csharp
SigningProfileValidationResult ValidateUnsignedBundle(
    SigningProfileValidationContext context)
```

Begin with `SigningProfileRequestValidator.Validate(Descriptor, context.Request)`. Then validate
every semantic rule owned by the consumer. Typical checks include:

- exact request project, profile, source repository, release version, signer policy, timestamp
  policy, artifact roles, names, sizes, and hashes;
- strict JSON with duplicate/unknown-property rejection, bounded depth, canonical casing and
  canonical encodings;
- exact manifest and build-evidence format/version;
- a bounded validity window compared with `ValidationTime`;
- manifest, request, and build-evidence agreement;
- portable executable structure, machine type, subsystem, product/version metadata, imports, and
  expected role-specific identity; and
- rejection of any pre-existing or partial Authenticode signature.

Open artifacts only with `context.ArtifactReader.OpenRead(exactFileName)`. The reader exposes no
directory or client path. Read with explicit bounds, compute hashes while reading, require expected
length/end-of-stream behavior, and avoid unbounded JSON/document models.

Return only a bounded `SigningProfileValidationError`. Do not include source values, paths,
exception text, or file contents in an error.

## 4. Finalize signed output

Implement:

```csharp
SigningProfileFinalizationResult FinalizeSignedBundle(
    SigningProfileFinalizationContext context)
```

The Worker calls this only after its Authenticode verifier has produced
`VerifiedAuthenticodeArtifact` evidence. Re-read the unsigned and signed artifacts through their
separate bounded readers. Match every verified role, filename, size, signed digest, signer
thumbprint, and whole-second timestamp to the descriptor and consumer manifest.

Produce the exact replacement bytes for the one declared JSON manifest. Serialization must be
deterministic: fixed property order and casing, canonical numbers/digests/timestamps, no unstable
whitespace, and no local environment data. Return only
`SigningProfileFinalizationResult.Success(bytes)` or a bounded failure.

Finalization must not mutate an executable, contact a service, read a clock other than the supplied
`FinalizedAt`, enumerate a directory, or select new policy.

## 5. Validate finalized output

Implement:

```csharp
SigningProfileValidationResult ValidateFinalizedBundle(
    SigningProfileFinalizedValidationContext context)
```

This is an independent complete check, not an assertion that finalization already ran. Validate the
final manifest schema and every relationship among the request, output inventory, artifact hashes,
verified Authenticode evidence, signer, timestamp, and release version. Both Worker and matching CLI
depend on this method to reject incomplete, mixed, or reinterpreted output.

Ensure failures include wrong signer, missing timestamp, altered signed file, stale unsigned hash,
duplicate evidence, unexpected role, partial signing, and a final manifest that describes different
bytes.

## 6. Build and package

Build the class library in Release mode using locked dependencies. Compute the final assembly
SHA-256 and create canonical ASCII/LF `profile-package.txt` beside it:

```text
Format=ArtifactSigningProfilePackageV1
PackageId=Example.Profile.Package
PackageVersion=1.0.0
AssemblyFile=Example.Profile.Package.dll
AssemblySha256=<lowercase-sha256>
Profile=ExampleBundleV1|1|Example.Profile.Package.ExampleBundleV1
```

Add one `Profile` line for each singleton type in the assembly. Package identifiers and versions
are case-sensitive reviewed identities. The directory contains no extra files.

The operator can inspect composition without building an appliance:

```powershell
.\eng\ProfileComposition\Compose-ProfileSet.ps1 `
  -Manifest C:\reviewed\profile-package\profile-package.txt `
  -OutputDirectory C:\reviewed\composition-output
```

Review generated registrations and `profile-set.lock`. Composition copies and references the exact
already-hashed assembly; it does not rebuild consumer source.

## 7. Align appliance policy

Before release composition, independently verify that:

- Gateway and Worker authorize the descriptor's exact project/profile/version;
- Gateway mTLS and signature identities map to the correct submitter and approver;
- production requires distinct submitter/approver SPKIs;
- Worker contains every referenced signer/timestamp alias and no unintended alias;
- the installed signer certificate satisfies the profile's signed-output identity rules;
- timestamp and revocation behavior match the profile's accepted evidence; and
- the same package-set digest is compiled/configured in Gateway, Worker, and CLI.

Clients never supply or override these relationships.

## Versioning

Increment `ProfileVersion` whenever accepted unsigned input, finalized output, validation semantics,
signer/timestamp compatibility, or any security decision changes. Retain old versions as separate
implementations while historical requests/results must remain verifiable.

Increment `PackageVersion` whenever package bytes change. A refactor that produces changed assembly
bytes needs a package version even if profile semantics are identical. A package-version-only change
must not reinterpret an existing `(ProfileId, ProfileVersion)`.

Never replace published bytes under an old version, and never silently point an old manifest at a
different assembly hash.

## Required tests

At minimum test:

- every descriptor allowlist and boundary;
- missing, duplicate, unknown, reordered, empty, oversized, truncated, and malformed input;
- strict/canonical JSON and Unicode/encoding edge cases;
- request/manifest/build-evidence disagreement;
- pre-signed, corrupt, wrong-machine, wrong-version, and role-swapped executables;
- wrong signer/timestamp evidence, partial signing, and signature/digest mismatch;
- deterministic finalization across repeated runs and cultures;
- finalized-output verification independent of finalization;
- every bounded failure code; and
- historical compatibility fixtures for each retained version.

Run formatting, warnings-denied build, unit/adversarial tests, dependency audit, and a secret scan in
the consumer repository. Native signing tests use only a generated disposable certificate and
timestamp authority.

The synthetic `ExampleEndpointBundleV1` and its tests in this repository demonstrate these patterns
at greater depth. They intentionally contain no consumer production policy.
