# Microsoft Artifact Signing

Microsoft Artifact Signing is an alternative Worker signing provider. The private Authenticode
key remains in Microsoft-operated HSMs; the appliance sends a digest-bearing signing request from
the fixed SignTool/Dlib integration and receives the short-lived signing certificate and signature.
Clients cannot select the provider, account, profile, endpoint, credentials, or SignTool options.

The Worker provider, rotating-leaf publisher verifier, release packager, and deployment V3 Windows
installer are implemented. A managed-provider release is not accepted merely because those source
paths exist: its exact client tools, Azure Arc host, identities, firewall representation, service
restarts, cold boot, update, rollback, and end-to-end signing flow must pass on a disposable target
before a retained appliance changes.

An isolated reference proof completed on 2026-08-09 using a Windows service virtual account, Azure
Arc system-assigned managed identity, client `1.0.128`, and a Public Trust Test profile. It included
a true power-off/power-on cycle, signer-role removal and restoration, HIMDS unavailability,
separate Artifact Signing and timestamp egress blocks, Dlib tampering, and a final recovery
signature. No production-profile role was used. This validates the component chain independently;
deployment V3 then applies the same constraints through the sealed appliance installer and remains
subject to the environment-specific acceptance gates below.

## Authentication model

The supported unattended design is:

```text
dedicated Windows machine or VM
  -> Azure Connected Machine Agent (Azure Arc)
  -> system-assigned managed identity through local HIMDS
  -> DefaultAzureCredential with every credential except ManagedIdentityCredential excluded
  -> hash-pinned Microsoft Artifact Signing Dlib
  -> one fixed Artifact Signing account and certificate profile
```

There is no client secret, interactive login, Azure CLI login, cached user token, environment
credential, or developer credential in this path. The Worker writes canonical per-job metadata
with exactly these excluded providers:

- `EnvironmentCredential`
- `WorkloadIdentityCredential`
- `SharedTokenCacheCredential`
- `VisualStudioCredential`
- `VisualStudioCodeCredential`
- `AzureCliCredential`
- `AzurePowerShellCredential`
- `AzureDeveloperCliCredential`
- `InteractiveBrowserCredential`

If the Arc managed identity is unavailable, authentication fails. Metadata is created only inside
the protected job directory, is hashed before and after SignTool execution, and is deleted before
an output can be published.

The SignTool child starts with an empty inherited environment. The Worker restores only the fixed
Windows `SystemRoot`, `SystemDrive`, and `ProgramData` paths, its protected per-job `TEMP`/`TMP`
directory, and the two compiled Azure Arc loopback endpoint variables. `SystemDrive` is required by
the Dlib's managed-host initialization and `ProgramData` is required for the HIMDS challenge-file
flow. It does not inherit `PATH`, a user profile, Azure CLI state, developer-tool state, or any
credential environment variable.

On Windows, add only the Worker virtual-service identity to the local `Hybrid Agent Extension
Applications` group. Do not make the Worker an administrator. Configure the Worker service to
depend on `himds` as well as Windows Time, and retain delayed automatic start. The Worker readiness
probe recognizes only the bounded local Arc HIMDS challenge response; an actual signing attempt
still proves token acquisition, Azure authorization, profile access, and service availability.

Service state is not proof of clock convergence. A reference Proxmox proof found a ten-hour
pre-sync error when QEMU presented a local-time RTC while Windows was configured for UTC. Match the
guest time-zone/RTC model, configure reviewed Windows Time peers, and prove the clock is correct
immediately after a cold boot. Request-freshness validation must remain fail closed while the clock
is wrong; do not widen validity windows to hide the condition.

## Azure prerequisites

1. Create an Artifact Signing account in a supported region.
2. Complete a Public identity validation.
3. Create a `Public Trust Test` certificate profile for the first proof.
4. Arc-enable the dedicated Windows machine and enable its system-assigned identity.
5. Assign `Artifact Signing Certificate Profile Signer` to the Arc machine principal at the test
   certificate-profile scope, not subscription or account scope.
6. Configure Sign Transactions diagnostic logs and an explicit storage lifecycle policy.

After the complete cold-boot matrix passes, create or select the production `Public Trust` profile
and grant the same role at that profile only. Remove the test-profile assignment when it is no
longer required.

`Public Trust Test` certificates are deliberately not publicly trusted. If the disposable proof
needs their test root in a Windows trust store, import that public root only into the isolated
disposable machine, record its thumbprint independently, and destroy or restore the machine after
the proof. Never add the test root to a retained production appliance or a general workstation.

Microsoft documentation:

- [SignTool/Dlib integration](https://learn.microsoft.com/azure/artifact-signing/how-to-signing-integrations)
- [Certificate lifecycle and subscriber EKU](https://learn.microsoft.com/azure/artifact-signing/concept-certificate-management)
- [Azure Arc managed identity authentication](https://learn.microsoft.com/azure/azure-arc/servers/managed-identity-authentication)
- [Azure Arc Connected Machine Agent network requirements](https://learn.microsoft.com/azure/azure-arc/servers/network-requirements)
- [Artifact Signing roles](https://learn.microsoft.com/azure/artifact-signing/tutorial-assign-roles)

## Pin the complete client toolset

Do not install or update the Dlib dynamically on the appliance. Acquire a reviewed x64
`Microsoft.ArtifactSigning.Client` NuGet package off-appliance, verify its NuGet signature and
independently authorized package SHA-256, and copy only its complete `bin/x64` directory into a
protected, versioned tools directory.

The Worker pins all of the following:

- exact x64 SignTool path, SHA-256, and four-part file version;
- exact `Azure.CodeSigning.Dlib.dll` path, SHA-256, and four-part file version; and
- one canonical inventory SHA-256 covering every leaf file in the Dlib directory.

The inventory is the SHA-256 of ordinal-filename-sorted UTF-8 records:

```text
<leaf-name> NUL <decimal-size> NUL <lowercase-file-sha256> LF
```

Nested directories, reparse points, hard-linked files, unsafe names, empty directories, and more
than 128 files are rejected. The complete inventory is checked before and after every signing
operation so replacing an Azure Identity, MSAL, runtime, or VC++ dependency fails closed even when
the main Dlib file is unchanged.

Inspect the selected package's `Azure.CodeSigning.Dlib.runtimeconfig.json`. Package `1.0.128`
targets `net8.0` but declares `rollForward: Major`; that is evidence that a later installed major
runtime may be selected technically, not a Microsoft support commitment. Native acceptance must
record the actual runtime loaded. Keep the Microsoft support question open because the published
prerequisite still names .NET 8 and .NET 8 reaches end of support in November 2026.

## Worker configuration V3

V3 is a closed provider union. Exactly one of `LocalMachineCertificate` or
`MicrosoftArtifactSigning` must be present and it must match `Provider`. V2 remains accepted only
for existing Local Machine configurations.

```json
{
  "SignerPolicyId": "ExampleMicrosoftPublicTrustV1",
  "TimestampPolicyId": "MicrosoftRfc3161V1",
  "Provider": "MicrosoftArtifactSigning",
  "MicrosoftArtifactSigning": {
    "Region": "JapanEast",
    "CodeSigningAccountName": "example-signing-account",
    "CertificateProfileName": "Example-PublicTrust-Test",
    "SignToolPath": "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.26100.0\\x64\\signtool.exe",
    "SignToolSha256": "<lowercase-sha256>",
    "SignToolFileVersion": "<four-part-version>",
    "DlibPath": "C:\\Program Files\\ArtifactSigning\\MicrosoftArtifactSigning\\1.0.128\\Azure.CodeSigning.Dlib.dll",
    "DlibSha256": "<lowercase-sha256>",
    "DlibFileVersion": "1.0.128.0",
    "ClientToolsInventorySha256": "<lowercase-sha256>",
    "ExpectedPublisherSubjectNameSha256": "<sha256-of-X500-subject-DER>",
    "RequiredPublisherEnhancedKeyUsageOid": "<public-trust-test-subscriber-eku-oid>",
    "TrustedPublisherRootThumbprints": [
      "<uppercase-root-thumbprint>"
    ],
    "SignToolTimeoutSeconds": 120,
    "AuthenticodeRevocationPolicy": "DisposableTestNoCheck"
  }
}
```

The endpoint and timestamp URL are derived from the closed region/provider policy. A configuration
cannot supply either URL. `RetainedLab` deliberately rejects this provider; use `DisposableTest`
for a Public Trust Test profile and `Production` for a Public Trust profile. The surrounding Worker,
Gateway, authorization, and receipt configuration must use the same deployment mode. The example
above is therefore a disposable-test signing-policy fragment, not a production configuration.

The modes are cryptographically separated by the required subscriber EKU namespace:

- `DisposableTest` accepts only a Public Trust Test subscriber EKU beginning
  `1.3.6.1.4.1.311.97.1.2.` and requires `DisposableTestNoCheck` because the Microsoft test chain
  is intentionally not publicly trusted.
- `Production` accepts only an account-specific Public Trust subscriber EKU beginning
  `1.3.6.1.4.1.311.97.` but rejects Microsoft's reserved `.97.1.*` namespace, and requires online
  Authenticode revocation checking.

Capture the exact EKU from the corresponding signed fixture. Never put the production subscriber
EKU in a test configuration or the test subscriber EKU in a production configuration.

The region enum covers the endpoints published with client `1.0.128`: Brazil South, Central US,
East US, Japan East, Korea Central, North Central US, North Europe, Poland Central, South Central
US, Switzerland North, West Central US, West Europe, West US, West US 2, and West US 3. A newly
announced region is rejected until its endpoint is added, tested, and released deliberately.

## Rotating-leaf verification

Artifact Signing leaf certificates rotate frequently and cannot be pinned by thumbprint or public
key. The Worker nevertheless records the actual leaf and timestamp-authority thumbprints in every
receipt. Acceptance is based on the stable publisher policy:

- Windows Authenticode trust succeeds;
- exactly one embedded SHA-256 Authenticode signer exists;
- exactly one valid SHA-256 RFC 3161 timestamp exists;
- the leaf has the code-signing EKU;
- for production Public Trust, the leaf has Microsoft's marker EKU
  `1.3.6.1.4.1.311.97.1.0`; Public Trust Test instead proves its distinct
  `1.3.6.1.4.1.311.97.1.2.*` subscriber namespace;
- the leaf has the exact account/profile subscriber EKU;
- the leaf's X.500 subject DER has the exact configured SHA-256; and
- a signer chain built at the trusted timestamp terminates at one configured root thumbprint.

Capture the subject digest, subscriber EKU, and root only from a successful test-profile signature
whose account/profile and correlation ID were independently verified. Do not copy a current leaf
thumbprint into the stable policy.

## Disposable proof and promotion

Use an unsigned, non-production fixture and record bounded evidence for this sequence:

1. No user is logged on; Azure CLI, PowerShell, Visual Studio, and developer credentials are absent.
2. The Worker virtual account is not an administrator and is the only appliance identity added to
   `Hybrid Agent Extension Applications`.
3. A direct Dlib test using the Public Trust Test profile succeeds and the correlation ID appears
   in Sign Transactions diagnostics.
4. The signed fixture has the expected subject, Public Trust Test subscriber EKU, trusted test
   root, SHA-256 file digest, and RFC 3161 timestamp. It must not satisfy the production Public
   Trust policy.
5. Reboot twice and submit immediately after boot. Readiness remains false while HIMDS is absent,
   then a later attempt succeeds without an interactive login or service restart.
6. Remove the profile-scoped signer role. Signing fails and no output is published. Restore the
   role and prove a later request succeeds.
7. Block the Arc identity endpoint, Artifact Signing endpoint, and timestamp endpoint in turn.
   Each case fails closed and produces no publishable result.
8. Change one Dlib dependency byte and prove the client-tools inventory check stops SignTool.
9. Build a sealed deployment V3 release and run its full install, restart, cold-boot,
   reconciliation, update, rollback, and end-to-end appliance matrix.

Only then create a new consumer profile version whose allowed signer and timestamp aliases name the
managed policies, deploy the production Public Trust profile configuration, grant the production
profile-scoped role, and run one separately approved canary request. Keep the prior signer generation
available for rollback until the canary receipt and Windows verification have been reviewed.

## Managed-provider egress

The Local Machine track uses a static private timestamp relay. Deployment V3 instead keeps the
same deny-by-default host policy and creates only process/service-scoped rules for the exact pinned
SignTool, the installed Microsoft-signed `himds` and `arcproxy` services, and DNS through the exact
configured resolver addresses. Worker and SignTool also receive only loopback TCP 40342 to the Arc
identity endpoint. SignTool receives Internet TCP 80/443 because the compiled Microsoft Dlib
selects the Artifact Signing and RFC 3161 endpoints and certificate-chain validation may require
HTTP. Arc processes receive TCP 443. No arbitrary application receives Internet egress.

The installer verifies the exact native firewall representation, Arc service paths, Microsoft
signatures, Worker-only membership in `Hybrid Agent Extension Applications`, and the complete
client-tools inventory. Application-layer TLS and the Worker's closed endpoint/provider policy
still authenticate the selected services. Azure Arc public-endpoint mode does not require a VPN.
Private Link is an optional later architecture and still does not eliminate every public
dependency.

Microsoft publishes the required Arc URLs and service tags and warns that allowing only an
endpoint's currently resolved IP is not reliable. Traditional per-host Windows Firewall rules do
not interpret Azure service tags or maintain Microsoft's changing FQDN/IP set. For a retained
production appliance, combine the host rules with one reviewed network contract:

- process/service-scoped outbound rules on the appliance plus an upstream firewall or proxy that
  enforces the documented FQDN/service-tag policy; or
- an approved, automatically refreshed IP policy derived from Microsoft's published service-tag
  data, with drift monitoring and a tested failure/refresh procedure; or
- Azure Arc Private Link over existing private connectivity, if its cost and remaining public
  endpoint requirements are accepted.

Deployment V3 names its host contract `ProcessScopedTlsValidatedInternet`; the value deliberately
does not claim that Windows Firewall enforces FQDNs or Azure service tags. A disposable acceptance
machine may rely on those exact process/service rules while the full appliance matrix runs. A
retained production release must additionally record which upstream contract above is in force,
or explicitly accept process-scoped public Internet egress as a documented residual risk. Never
replace it with an all-program outbound rule merely to regain availability.
