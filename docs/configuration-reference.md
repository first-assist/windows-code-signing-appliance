# Configuration reference

All service and client JSON is strict and case-sensitive. Properties use PascalCase. Duplicate or
unknown properties, comments, trailing commas, numeric enum aliases, excessive nesting, invalid
canonical values, and oversized files are rejected. Configuration files are reviewed release or
owner-controlled inputs; there is no runtime configuration API.

This document describes the current schema families. The parser and tests remain authoritative.
Do not copy placeholder digests, identities, paths, addresses, or trust values into a deployment.

## Common values

- SHA-256 digests are exactly 64 lowercase hexadecimal characters.
- Windows certificate thumbprints are uppercase hexadecimal without spaces.
- Profile and policy identifiers are safe, bounded identifiers.
- Absolute URLs are canonical and contain no user information, query, or fragment unless a
  protocol explicitly permits it.
- Production service addresses are exact private unicast addresses, not wildcards or subnets.
- Production CMS and Authenticode verification use online revocation.
- Timeout and collection bounds are enforced by each component.

The deployment modes are:

- `Production`: private networking, independent approval, public PKI trust, and online revocation;
- `DisposableTest`: generated identities and loopback/disposable acceptance only; and
- `RetainedLab`: certificate-pinned compatibility testing only, never public production trust.

The public repository does not provide retained-lab provisioning automation. New users should use
`DisposableTest` for generated-key acceptance and a reviewed `Production` configuration for real
operation.

## CLI configuration V1

Format identifier: `ArtifactSigningCliConfigurationV1`.

Use `--config <absolute-path>` to select a file. Without it, the CLI first checks
`ARTIFACT_SIGNING_CONFIG`, then uses `artifact-signing/client.json` beneath the operating system's
Application Data directory. An explicit argument is clearer for unattended release jobs.

The configuration and referenced private-key/password files must be direct owner-only files. On
Unix, sensitive files must have mode `0600`. Keep submitter and approver configurations separate.

### Top-level properties

| Property | Meaning |
| --- | --- |
| `Format` | Must be `ArtifactSigningCliConfigurationV1` |
| `Mode` | `Production`, `DisposableTest`, or `RetainedLab` |
| `ServiceUri` | Canonical private HTTPS Gateway origin |
| `ServerCertificateSha256` | Exact Gateway TLS leaf certificate SHA-256 |
| `ServerSpkiSha256` | Exact Gateway TLS subject-public-key-info SHA-256 |
| `ClientIdentity` | Client certificate/private-key provider |
| `SubmitterTrust` | Trust used to verify signed request/review material |
| `ReceiptTrust` | Trust used to verify Worker receipts |

The two server pins are both required; ordinary platform TLS trust alone is insufficient.

### `ClientIdentity`

| Property | Meaning |
| --- | --- |
| `Provider` | `PemFiles` or `WindowsCurrentUserStore` |
| `CertificatePath` | Absolute public certificate path for `PemFiles`; otherwise `null` |
| `PrivateKeyPath` | Absolute private-key path for `PemFiles`; otherwise `null` |
| `PrivateKeyPasswordFile` | Optional absolute owner-only password file; never put the password inline |
| `CertificateThumbprint` | Unique Current User store certificate for `WindowsCurrentUserStore`; otherwise `null` |

The Windows provider is Windows-only and resolves one non-exportable Current User certificate with
an accessible private key. The PEM provider is appropriate for protected Linux automation. Never
store client keys under a source checkout or artifact bundle.

### CLI trust object

`SubmitterTrust` and `ReceiptTrust` contain:

| Property | Meaning |
| --- | --- |
| `ExpectedSignerSpkiSha256` | Exact expected signer public-key digest |
| `ExpectedSignerCertificateSha256` | `null` except certificate-pinned `RetainedLab` mode |
| `RequiredEnhancedKeyUsageOid` | Required canonical numeric EKU OID |
| `TrustedRootCertificatePaths` | Absolute paths to public root certificates |
| `ExtraCertificatePaths` | Absolute paths to required public intermediates |
| `RevocationPolicy` | `Online` for `Production`, `DisposableTestNoCheck` for `DisposableTest`, or `RetainedLabPinned` for `RetainedLab` |
| `UrlRetrievalTimeoutSeconds` | Certificate URL retrieval timeout, 1 through 15 |

Production requires `Online` and forbids a leaf-certificate pin. Offline and no-check policies are
not production substitutes.

## Gateway configuration V2

Format identifier: `ArtifactSigningGatewayConfigurationV2`. The installed file is protected as
`C:\Program Files\ArtifactSigning\Gateway\gateway.json`.

### Top-level properties

| Property | Meaning |
| --- | --- |
| `Format` | Must be `ArtifactSigningGatewayConfigurationV2` |
| `Mode` | Deployment mode |
| `GatewayServiceSid` | Exact installed Gateway virtual-service SID |
| `WorkerServiceSid` | Exact installed Worker virtual-service SID |
| `ProfileSetSha256` | Digest of the statically compiled `profile-set.lock` |
| `ListenAddress` | One exact private address in production |
| `ListenPort` | Private HTTPS API port |
| `ServerCertificateThumbprint` | Unique Local Machine Gateway TLS certificate |
| `AuthorizationPolicies` | Nonempty closed project/profile authorization list |
| `Auditors` | Closed read-only auditor list; may be empty |
| `ReceiptTrust` | Public trust for Worker receipt verification |

The installer renders service SIDs, listen address/port, TLS thumbprint, and profile-set digest from
fixed reviewed substitutions. The service rejects a compiled/configured package-set mismatch.

### Gateway authorization policy

Each `AuthorizationPolicies` item contains:

| Property | Meaning |
| --- | --- |
| `ProjectId` | Exact project identifier accepted by this policy |
| `ProfileId` | Exact installed profile identifier |
| `ProfileVersion` | Positive installed profile version |
| `SubmitterClient` | Exact submitter mTLS identity |
| `SubmitterTrust` | CMS trust for the submitter signature |
| `ApproverClient` | Exact approver mTLS identity |
| `ApproverTrust` | CMS trust for the approval signature |
| `RequireDistinctSubmitterAndApprover` | Must be `true` in production |

A Gateway client identity has `CertificateSha256` and `SubjectPublicKeyInfoSha256`. Both must match
the presented mTLS certificate. Production also requires submitter and approver SPKIs to differ.

An auditor item contains `ProjectId`, `ProfileId`, `ProfileVersion`, and `Client`. Auditors can read
authorized state/evidence but cannot submit or approve.

### Gateway trust object

Gateway signature and receipt trust contains:

| Property | Meaning |
| --- | --- |
| `ExpectedSignerSpkiSha256` | Exact signer public-key digest |
| `ExpectedSignerCertificateSha256` | Omitted except in `RetainedLab` mode |
| `RequiredEnhancedKeyUsageOid` | Required signer EKU |
| `TrustedRootThumbprints` | Public roots in reviewed Local Machine stores |
| `ExtraCertificateThumbprints` | Required public intermediate certificates |
| `RevocationPolicy` | CMS revocation policy allowed by mode |
| `UrlRetrievalTimeoutSeconds` | Retrieval timeout, 1 through 15 |

Certificate collections are bounded. Install only the public trust needed by the closed policies.

## Worker configuration V3

Format identifier: `ArtifactSigningWorkerConfigurationV3`. V3 keeps the V2 top-level Worker,
authorization, and receipt properties but replaces each flat signing policy with a closed provider
union.

Every `SigningPolicies` item has:

| Property | Meaning |
| --- | --- |
| `SignerPolicyId` | Alias referenced by compiled profile descriptors |
| `TimestampPolicyId` | Alias referenced by compiled profile descriptors |
| `Provider` | Exactly `LocalMachineCertificate` or `MicrosoftArtifactSigning` |
| `LocalMachineCertificate` | Present only when selected by `Provider` |
| `MicrosoftArtifactSigning` | Present only when selected by `Provider` |

Unknown, missing, null, dual, or provider-mismatched branches are rejected. Client requests still
contain only policy aliases and cannot select a provider or any provider value.

`LocalMachineCertificate` contains the same signing properties documented for V2 below. Production
requires `Online`; `RetainedLab` additionally requires the exact certificate and SPKI digests.

`MicrosoftArtifactSigning` contains:

| Property | Meaning |
| --- | --- |
| `Region` | Closed Artifact Signing region enum mapped to a compiled endpoint; see the managed-provider guide |
| `CodeSigningAccountName` | Fixed safe account name |
| `CertificateProfileName` | Fixed safe certificate-profile name |
| `SignToolPath` | Absolute reviewed x64 SDK `signtool.exe` path |
| `SignToolSha256` | Exact executable SHA-256 |
| `SignToolFileVersion` | Exact canonical four-part file version |
| `DlibPath` | Absolute `Azure.CodeSigning.Dlib.dll` path |
| `DlibSha256` | Exact Dlib SHA-256 |
| `DlibFileVersion` | Exact canonical four-part Dlib file version |
| `ClientToolsInventorySha256` | Canonical digest of every direct file beside the Dlib |
| `ExpectedPublisherSubjectNameSha256` | SHA-256 of the accepted publisher X.500 subject DER |
| `RequiredPublisherEnhancedKeyUsageOid` | Exact stable Artifact Signing subscriber EKU; Public Trust Test must use `1.3.6.1.4.1.311.97.1.2.*`, while production must use the account-specific `1.3.6.1.4.1.311.97.*` namespace outside Microsoft's reserved `.97.1.*` branch |
| `TrustedPublisherRootThumbprints` | One through eight accepted public root thumbprints |
| `SignToolTimeoutSeconds` | Direct process timeout, 1 through 120 |
| `AuthenticodeRevocationPolicy` | `Online` in production or `DisposableTestNoCheck` in disposable tests |

The Microsoft endpoint, managed-identity loopback endpoints, timestamp URL, and credential
exclusions are derived fixed policy and are not configuration properties. The provider is rejected
in `RetainedLab`. A test subscriber EKU cannot be parsed in `Production`, and a production
subscriber EKU cannot be parsed in `DisposableTest`. See
[Microsoft Artifact Signing](microsoft-artifact-signing.md) for the complete identity,
rotating-leaf, inventory, and acceptance rules.

## Worker configuration V2 (legacy Local Machine provider)

Format identifier: `ArtifactSigningWorkerConfigurationV2`. The installed file is protected as
`C:\Program Files\ArtifactSigning\Worker\worker.json`.

V2 remains parser-compatible for installed Local Machine generations and is the only format
rendered by legacy installer `0.3.2`. It cannot select Microsoft Artifact Signing. Installer
`0.4.1` renders managed releases as V3 rather than adding managed fields to V2. For managed
production deployments it also owns two fixed auto-resolved Windows Firewall keywords for
`www.microsoft.com` and `oneocsp.microsoft.com`. They are not deployment-supplied values and are
usable only by the Worker certificate-status rule on TCP 80/443.

### Top-level properties

| Property | Meaning |
| --- | --- |
| `Format` | Must be `ArtifactSigningWorkerConfigurationV2` |
| `Mode` | Deployment mode matching Gateway |
| `WorkerServiceSid` | Exact installed Worker virtual-service SID |
| `GatewayServiceSid` | Exact installed Gateway virtual-service SID |
| `ProfileSetSha256` | Exact compiled profile-set digest matching Gateway and CLI |
| `AuthorizationPolicies` | Worker-side signature authorization list |
| `SigningPolicies` | Fixed installed signer/timestamp policies |
| `Receipt` | Worker receipt identity and public verification policy |

Worker authorization repeats `ProjectId`, `ProfileId`, `ProfileVersion`, `SubmitterTrust`,
`ApproverTrust`, and `RequireDistinctSubmitterAndApprover`. It deliberately does not trust the
Gateway's earlier result.

### Signing policy

Each `SigningPolicies` item contains:

| Property | Meaning |
| --- | --- |
| `SignerPolicyId` | Alias referenced by compiled profile descriptors |
| `TimestampPolicyId` | Alias referenced by compiled profile descriptors |
| `SignToolPath` | Absolute reviewed x64 SDK `signtool.exe` path |
| `SignToolSha256` | Exact executable SHA-256 |
| `SignToolFileVersion` | Exact four-part file version |
| `SignerCertificateThumbprint` | Unique Local Machine Authenticode certificate |
| `SignerCertificateSha256` | Omitted in production; retained-lab leaf pin only |
| `SignerSubjectPublicKeyInfoSha256` | Omitted in production; retained-lab pin only |
| `TimestampUrl` | Fixed HTTP(S) RFC 3161 endpoint selected by the operator |
| `SignToolTimeoutSeconds` | Direct process timeout, 1 through 120 |
| `AuthenticodeRevocationPolicy` | `Online` in production; bounded test policies in test modes |

The current hardened deployment substitutes the timestamp URL from the exact private relay address
and port. SignTool is started directly with `UseShellExecute=false`; no shell or client-supplied
argument is involved.

### Receipt object

`Receipt` contains `CertificateThumbprint` and `Trust`. The thumbprint resolves the Worker-only
receipt key. The nested trust object has the same SPKI, optional retained-lab certificate pin, EKU,
root/intermediate thumbprints, revocation policy, and URL timeout fields described for Gateway
trust.

## Timestamp relay configuration V1

Format identifier: `ArtifactSigningTimestampRelayConfigurationV1`. Install the file at
`/etc/artifact-signing/timestamp-relay.json`, owned by the dedicated service account with mode
`0600` and exactly one hard link.

| Property | Meaning and bounds |
| --- | --- |
| `Format` | Must be `ArtifactSigningTimestampRelayConfigurationV1` |
| `Mode` | `Production` or `DisposableTest` |
| `BindAddress` | Exact private non-loopback address in production |
| `BindPort` | 1024 through 65535 |
| `AllowedClientAddresses` | One to sixteen exact private client addresses |
| `UpstreamUrl` | One canonical HTTPS URL in production |
| `UpstreamAddresses` | One to four exact IP destinations for that authority |
| `ConnectTimeoutSeconds` | 1 through 5 |
| `TotalTimeoutSeconds` | 2 through 15 and greater than connect timeout |
| `RequestsPerMinute` | 1 through 30 |

`UpstreamAddresses` is a connection allowlist, not a DNS cache. The relay validates the configured
hostname through normal TLS trust while connecting only to the listed addresses. Review address
rotation as a configuration and firewall release.

The example under `deploy/linux/timestamp-relay/` uses documentation-only addresses and an
`.invalid` hostname. Replace every value and review the resulting service and firewall together.

## Profile package manifest V1

`profile-package.txt` is canonical ASCII/LF `Name=Value` data:

```text
Format=ArtifactSigningProfilePackageV1
PackageId=<safe-identifier>
PackageVersion=<canonical-semver>
AssemblyFile=<safe-leaf-dll-name>
AssemblySha256=<lowercase-sha256>
Profile=<profile-id>|<positive-version>|<static-singleton-type-name>
```

One or more `Profile` lines follow the five fixed fields. The package directory contains only the
manifest and its declared direct single-link managed assembly. Composition rejects extra files,
duplicate identities, unsafe names, hash drift, unsupported assembly shape, and nondeterministic
registrations.

## Installer deployment V2

`deployment.txt` is canonical ASCII/LF and contains exactly:

```text
Format=ArtifactSigningInstallerDeploymentV2
ReleaseVersion=<service-release-semver>
SourceCommit=<full-lowercase-commit>
InstallerVersion=<exact-installer-version>
GatewayVersion=<exact-gateway-version>
WorkerVersion=<exact-worker-version>
CliVersion=<exact-cli-version>
ProfileSetSha256=<lowercase-package-set-sha256>
GatewayListenAddress=<exact-private-address>
GatewayListenPort=<private-api-port>
GatewayIngressRemoteAddresses=<comma-separated-exact-client-addresses>
TimestampRelayAddress=<exact-private-relay-address>
TimestampRelayPort=<relay-port>
CertificateStatusRemoteAddresses=<comma-separated-exact-addresses-or-empty>
TimeServerAddresses=<comma-separated-exact-addresses>
GatewayTlsCertificateThumbprint=<uppercase-thumbprint>
ReceiptCertificateThumbprint=<different-uppercase-thumbprint>
AuthenticodeCertificateThumbprint=<different-uppercase-thumbprint>
SignToolPath=<absolute-reviewed-x64-sdk-path>
SignToolSha256=<lowercase-sha256>
SignToolFileVersion=<exact-four-part-version>
```

The release builder requires the source `HEAD` to equal `SourceCommit`. Component values must match
the files being published. The installer verifies exact network, certificate, SignTool, profile
set, component, and inventory binding before services can start.

## Installer deployment V3

V3 selects only `MicrosoftArtifactSigning`. It contains every V2 key, but
`TimestampRelayAddress`, `TimestampRelayPort`, and `AuthenticodeCertificateThumbprint` must be
empty. It adds exactly:

| Key | Meaning |
| --- | --- |
| `SigningProvider` | Must be `MicrosoftArtifactSigning` |
| `DnsServerAddresses` | One through eight exact DNS server addresses used by the service-scoped DNS rules |
| `ManagedEgressPolicy` | Must be `ProcessScopedTlsValidatedInternet`; only the declared signed processes/services receive Internet egress |
| `MicrosoftArtifactSigningRegion` | Closed region enum compiled by the Worker |
| `MicrosoftArtifactSigningAccountName` | Fixed Artifact Signing account |
| `MicrosoftArtifactSigningCertificateProfileName` | Fixed certificate profile |
| `MicrosoftArtifactSigningDlibSha256` | Exact Dlib digest |
| `MicrosoftArtifactSigningDlibFileVersion` | Exact four-part Dlib file version |
| `MicrosoftArtifactSigningClientToolsInventorySha256` | Canonical inventory digest for every direct client-tools file |
| `MicrosoftArtifactSigningRuntimeMajor` | Required installed shared .NET runtime major |
| `MicrosoftArtifactSigningExpectedPublisherSubjectNameSha256` | Stable publisher subject-DER digest |
| `MicrosoftArtifactSigningRequiredPublisherEnhancedKeyUsageOid` | Exact subscriber EKU |
| `MicrosoftArtifactSigningTrustedPublisherRootThumbprints` | One through eight comma-separated uppercase roots |
| `MicrosoftArtifactSigningSignToolTimeoutSeconds` | One through 120 seconds |
| `MicrosoftArtifactSigningAuthenticodeRevocationPolicy` | `Online` or `DisposableTestNoCheck`, matching the Worker mode |

V3 packages the complete tools directory at
`C:\Program Files\ArtifactSigning\Worker\MicrosoftArtifactSigningClient`. The installer verifies
the directory inventory, Dlib, runtime, Arc service definitions and Microsoft signatures, HIMDS
status, service-group isolation, exact service dependencies, process-scoped loopback identity
access, and provider-specific firewall rules before the appliance starts.

## Fixed template substitutions

The Gateway template may contain each required placeholder exactly once:

- `__GATEWAY_SERVICE_SID__`
- `__WORKER_SERVICE_SID__`
- `__GATEWAY_LISTEN_ADDRESS__`
- `__GATEWAY_LISTEN_PORT__`
- `__GATEWAY_TLS_THUMBPRINT__`
- `__PROFILE_SET_SHA256__`

The V2 Worker template may contain each required placeholder exactly once:

- `__GATEWAY_SERVICE_SID__`
- `__WORKER_SERVICE_SID__`
- `__RECEIPT_THUMBPRINT__`
- `__AUTHENTICODE_THUMBPRINT__`
- `__SIGNTOOL_PATH_JSON__`
- `__SIGNTOOL_SHA256__`
- `__SIGNTOOL_FILE_VERSION__`
- `__TIMESTAMP_URL__`
- `__PROFILE_SET_SHA256__`

The V3 managed Worker template replaces the local certificate/timestamp placeholders with:

- `__SIGNING_PROVIDER__`
- `__MICROSOFT_ARTIFACT_SIGNING_REGION__`
- `__MICROSOFT_ARTIFACT_SIGNING_ACCOUNT_NAME__`
- `__MICROSOFT_ARTIFACT_SIGNING_CERTIFICATE_PROFILE_NAME__`
- `__MICROSOFT_ARTIFACT_SIGNING_DLIB_PATH_JSON__`
- `__MICROSOFT_ARTIFACT_SIGNING_DLIB_SHA256__`
- `__MICROSOFT_ARTIFACT_SIGNING_DLIB_FILE_VERSION__`
- `__MICROSOFT_ARTIFACT_SIGNING_CLIENT_TOOLS_INVENTORY_SHA256__`
- `__MICROSOFT_ARTIFACT_SIGNING_EXPECTED_PUBLISHER_SUBJECT_NAME_SHA256__`
- `__MICROSOFT_ARTIFACT_SIGNING_REQUIRED_PUBLISHER_EKU_OID__`
- `__MICROSOFT_ARTIFACT_SIGNING_TRUSTED_PUBLISHER_ROOTS_JSON__`
- `__MICROSOFT_ARTIFACT_SIGNING_SIGNTOOL_TIMEOUT_SECONDS__`
- `__MICROSOFT_ARTIFACT_SIGNING_AUTHENTICODE_REVOCATION_POLICY__`

It also requires the two service SIDs, receipt thumbprint, SignTool path/hash/version, and profile
set digest from the common list. Every required placeholder occurs exactly once; any unresolved or
extra placeholder fails the build/install boundary.

No arbitrary token expansion is performed. Project/profile authorization, trust roots, SPKI pins,
EKUs, signer/timestamp aliases, timeouts, revocation policy, and all other policy remain literal
reviewed template content.

## Validation references

For executable dummy configurations, consult:

- `tests/ArtifactSigning.Cli.Tests/CliConfigurationTests.cs`;
- `tests/ArtifactSigning.Gateway.Tests/GatewayServiceConfigurationTests.cs`;
- `tests/ArtifactSigning.Worker.Tests/WorkerServiceConfigurationTests.cs`; and
- `tests/ArtifactSigning.TimestampRelay.Tests/TimestampRelayConfigurationTests.cs`.

Those fixtures contain synthetic values for parser tests. They are not deployment templates.
