# Windows installation and hardening

## Scope and acceptance boundary

The installer creates the dedicated Windows Gateway/Worker appliance. It is not a certificate
enrollment tool, a general software installer or a service self-updater. Installer version
`0.4.1` accepts only a closed, hash-bound release package, an exact compiled profile set and fixed
operations.

Source review or a successful package build is not native Windows acceptance. A release becomes
eligible for appliance deployment only after a disposable Windows VM proves installation,
service-identity isolation, exact ACLs, two restarts, reboot, rollback and generated-key signing.
Never run these instructions on a retained signer, an acceptance template, or an ordinary
workstation.

The installer has two closed tracks. Deployment V2 installs the Local Machine certificate
provider. Deployment V3 installs Microsoft Artifact Signing with a complete pinned client-tools
directory and Azure Arc system-assigned managed identity. It does not enroll Arc, install the
Microsoft client package, install .NET, create certificates, or grant Azure RBAC; those are
separately reviewed prerequisites. Follow `docs/microsoft-artifact-signing.md` for the managed
identity, rotating-leaf, egress, and native acceptance gates.

## Prerequisites

Complete these steps on a new dedicated VM before the installer applies deny-by-default egress:

1. Finish Windows Update and remove general-purpose installation media.
2. Configure a static address on the isolated signing network. The deployment policy supplies the
   fixed Windows Time peer addresses applied by the installer.
3. Install one reviewed x64 Windows SDK SignTool beneath
   `%ProgramFiles(x86)%\Windows Kits\10\bin\<four-part-version>\x64\signtool.exe`.
4. Generate distinct Gateway TLS and receipt RSA identities inside `LocalMachine\My` with the
   Microsoft Software Key Storage Provider, machine scope and `ExportPolicy=None`. For deployment
   V2 only, also generate a distinct Authenticode identity. Do not create or transfer a PFX.
5. Install only the required public submitter, approver, receipt and TSA trust into the reviewed
   Local Machine public stores.
6. Record public thumbprints, SPKI SHA-256 digests, certificate validity and required EKUs. Do not
   record certificate contents or private-key storage names in ordinary evidence.
7. For deployment V2, deploy and validate the timestamp relay on a separate contained Linux
   workload. For deployment V3, Arc-enable the machine, install the declared .NET runtime, and
   grant its machine principal the signer role at one certificate-profile scope only.

The installer refuses missing, ambiguous, ephemeral, exportable, non-CNG or shared private-key
state. It never calls an export operation.

## Release package

Build from a clean full commit using the SDK pinned by `global.json`. The Gateway and Worker
configuration templates are complete reviewed service configurations with only these fixed
machine substitutions:

- Gateway template: `__GATEWAY_SERVICE_SID__`, `__WORKER_SERVICE_SID__`,
  `__GATEWAY_LISTEN_ADDRESS__`, `__GATEWAY_LISTEN_PORT__` and
  `__GATEWAY_TLS_THUMBPRINT__`, and `__PROFILE_SET_SHA256__`;
- Worker template: both service SID placeholders, `__RECEIPT_THUMBPRINT__`,
  `__AUTHENTICODE_THUMBPRINT__`, `__SIGNTOOL_PATH_JSON__`, `__SIGNTOOL_SHA256__`,
  `__SIGNTOOL_FILE_VERSION__`, `__TIMESTAMP_URL__` and `__PROFILE_SET_SHA256__`.

Every required placeholder occurs exactly once. No other placeholder is accepted. Project,
profile, submitter, approver, public trust and revocation policies are compiled/reviewed content
in the templates; they are not installer command-line input.
Gateway, configuration and installer payloads are flat allowlisted file sets. Worker payloads may
add only safe nested paths; deployment V3 uses exactly
`Worker/MicrosoftArtifactSigningClient/` for the complete direct-file client-tools inventory.
Every directory and file is direct, non-reparse, closed by the inventory, and assigned the same
exact protected installation ACL.

`deployment.txt` is canonical ASCII/LF `Name=Value` data with exactly:

```text
Format=ArtifactSigningInstallerDeploymentV2
ReleaseVersion=<service-release-semver>
SourceCommit=<full-lowercase-commit>
InstallerVersion=0.4.1
GatewayVersion=0.8.3
WorkerVersion=0.11.2
CliVersion=0.5.1
ProfileSetSha256=<lowercase-package-set-sha256-from-profile-set.lock>
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

Deployment V3 contains all V2 keys, keeps the relay and Local Machine Authenticode values empty,
and adds the closed managed-provider policy:

```text
Format=ArtifactSigningInstallerDeploymentV3
...
TimestampRelayAddress=
TimestampRelayPort=
AuthenticodeCertificateThumbprint=
SigningProvider=MicrosoftArtifactSigning
DnsServerAddresses=<comma-separated-exact-DNS-addresses>
ManagedEgressPolicy=ProcessScopedTlsValidatedInternet
MicrosoftArtifactSigningRegion=<closed-region-name>
MicrosoftArtifactSigningAccountName=<fixed-account-name>
MicrosoftArtifactSigningCertificateProfileName=<fixed-profile-name>
MicrosoftArtifactSigningDlibSha256=<lowercase-sha256>
MicrosoftArtifactSigningDlibFileVersion=<four-part-version>
MicrosoftArtifactSigningClientToolsInventorySha256=<lowercase-sha256>
MicrosoftArtifactSigningRuntimeMajor=<required-shared-runtime-major>
MicrosoftArtifactSigningExpectedPublisherSubjectNameSha256=<lowercase-sha256>
MicrosoftArtifactSigningRequiredPublisherEnhancedKeyUsageOid=<subscriber-eku>
MicrosoftArtifactSigningTrustedPublisherRootThumbprints=<comma-separated-uppercase-thumbprints>
MicrosoftArtifactSigningSignToolTimeoutSeconds=<1-through-120>
MicrosoftArtifactSigningAuthenticodeRevocationPolicy=<Online-or-DisposableTestNoCheck>
```

The managed Worker template uses `ArtifactSigningWorkerConfigurationV3` and the corresponding
`__MICROSOFT_ARTIFACT_SIGNING_*__` placeholders documented in the configuration reference. The
builder requires `-MicrosoftArtifactSigningClientToolsDirectory` and copies every direct file into
the closed Worker payload. Installation re-computes the complete canonical inventory, verifies the
Dlib hash and file version, and proves that the declared shared runtime major is installed.

The Gateway opens the local Worker notification pipe with the same individual write,
read-attributes, DACL-read and synchronization rights granted to its virtual-service SID. It does
not request generic write because the named-pipe instance-creation bit aliases one of that generic
mask's components; the hardened Worker DACL intentionally withholds data read and instance creation
from the Gateway.

After exact-digest approval, the Gateway also replaces the moved request tree's retained
pending ACL with a protected exact ready-record ACL: SYSTEM, Administrators and Gateway receive
full control, while Worker receives only `ReadAndExecute`. Every compiled-profile file and both
fixed directories are direct and reverified before the Worker is notified. Startup redispatch
repairs or rejects the same ACL; pending records never receive Worker access.

After the Worker has completed Authenticode signing, finalized validation, receipt signing and the
closed result inventory, it atomically moves the request tree from Worker-only `work` to `output`
while its durable state remains `Signing`. A same-volume NTFS move retains the source child ACL.
The Worker then derives the exact result files from the compiled profile, validates every
directory and direct single-link file, and projects protected explicit ACLs. SYSTEM,
Administrators and Worker receive full control; Gateway receives only `ReadAndExecute`. Files are
set first, then the bundle directory, and the request directory last so Gateway cannot traverse a
partially projected tree. The Worker revalidates the complete inventory and ACLs before recording
`Signed` or publishing terminal status. Projection failure maps to `OutputPublicationFailed` and
the sole tree is quarantined. Startup repeats the repair-or-deny check before republishing any
durable signed status. The Gateway never receives access to `work` or incomplete artifacts.

The file contains public policy only. IP ranges, hostnames, commands, credentials and secret
values are not accepted.

Build:

```powershell
.\installer\Build-ArtifactSigningRelease.ps1 `
  -GatewayConfigurationTemplate C:\reviewed\gateway.template.json `
  -WorkerConfigurationTemplate C:\reviewed\worker.template.json `
  -Deployment C:\reviewed\deployment.txt `
  -ProfilePackageManifest C:\reviewed\profile-package\profile-package.txt `
  -OutputRoot C:\release\artifact-signing-unique-output
```

Add `-MicrosoftArtifactSigningClientToolsDirectory C:\reviewed\client\bin\x64` only for deployment
V3.

Azure Arc HIMDS on Windows binds its identity endpoint to IPv4 loopback. The managed rules permit
only `127.0.0.1:40342` for the Worker and the pinned SignTool process. Windows rejects an explicit
IPv6 loopback destination in a firewall address filter, and the installer does not widen that
filter to a subnet or `Any` as a workaround.

Run the builder under PowerShell 7 from a clean worktree whose exact HEAD equals the deployment
`SourceCommit`; the output directory must not already exist. The builder composes and hash-pins the
reviewed profile packages, publishes deterministic self-contained `win-x64` single-file services
and CLI, removes PDBs, copies the installer, carries `profiles/profile-set.lock`, and emits
`release-inventory.txt`. Record the printed full commit and
`RELEASE_INVENTORY_SHA256` through an independent channel. The inventory digest—not a path or
display name—is the installation authorization.

The closed inventory rejects extra/missing/duplicate paths, traversal, reparse points, hard links,
configuration files hidden in the payload, key-container extensions, private-key PEM markers,
size/hash drift and noncanonical text. The package contains no certificate or private key.

The exact ACL setter and verifier explicitly allow an empty read-and-execute SID collection. This
is the administrator-only policy used by installer control files and directories; it does not add
an access rule. The declaration is required because Windows PowerShell rejects an empty collection
for a mandatory array parameter before the function body otherwise runs.

The installer invokes only the fixed Windows Service Control Manager tool resolved from the
Windows special folder as `System32\sc.exe`. Its leaf and every directory ancestor must be direct
and non-reparse. Windows projects serviced operating-system files from the Component Store by hard
link, so this one fixed Windows Resource Protection path is not subject to the package-file
single-hard-link rule. Package, staged and installed product files remain single-link-only.
Gateway and Worker are first created disabled, assigned their exact virtual service accounts, and
only then configured for delayed automatic start. Worker depends exactly on `W32Time` for V2 and
exactly on `himds` plus `W32Time` for V3. Gateway has exactly one dependency, Worker.

Installer failures are projected only as fixed operation phases. In addition to protected staging,
the appliance install distinguishes input/existing-state validation, update preparation, payload,
service definition/identity, configuration, installed ACL/state, SignTool/component validation,
key ACL, Event Log, firewall, control-state, service-start, audit and cleanup boundaries. Raw
PowerShell exceptions, paths and operating-system output are not returned to the controller.

## Clean install

Use an elevated local console or an independently secured out-of-band management console. Applying
the firewall during a remote network session can intentionally terminate that session.

```powershell
.\installer\stage-artifact-signing-release.ps1 `
  -Source C:\reviewed\artifact-signing-reviewed-release `
  -ExpectedReleaseHash <independently-supplied-lowercase-sha256>

C:\ProgramData\ArtifactSigningInstaller\staging\installer\install-artifact-signing-service.ps1 `
  -ExpectedReleaseHash <same-independent-sha256> `
  -Mode Install
```

The installer:

1. verifies the complete staged package;
2. copies exact service bytes beneath `%ProgramFiles%\ArtifactSigning`;
3. creates delayed-auto virtual-account services with bounded restart recovery;
4. resolves their service SIDs and renders only the fixed placeholders;
5. applies exact protected ACLs to every installed file and fixed state directory;
6. verifies SignTool path, hash, four-part version and component versions;
7. validates non-exportable machine CNG keys and applies Gateway-only TLS and Worker-only receipt
   key ACLs; V2 also applies the Authenticode key ACL, while V3 validates the pinned client tools
   and reconciles only Worker into `Hybrid Agent Extension Applications`;
8. registers three fixed Application Event Log sources;
9. sets all Windows Firewall profiles to inbound/outbound deny by default and adds only the
   reviewed Gateway ingress, provider-specific process/service egress, certificate-status, DNS,
   Arc, and time rules applicable to the selected provider;
10. configures `W32Time` for the exact deployment IPs in manual client mode, makes it automatic,
    restarts it, requires a successful bounded resynchronization, and verifies the persisted
    service and registry policy;
11. records a SYSTEM/Administrators-only installed inventory and starts Worker before Gateway; and
12. removes the protected staging generation only after success.

If installation fails, do not broaden an ACL or firewall rule to make it start. Preserve the fixed
failure code, stop both services and investigate from the clean pre-key snapshot or protected
rollback generation.

## Verification and readiness

Run after install, twice after separate Worker/Gateway restarts, and after reboot:

```powershell
C:\Program Files\ArtifactSigning\Installer\verify-artifact-signing-service.ps1
```

Verification fails on service image/account/start/recovery drift, unexpected installed bytes,
configuration drift, state/control/key ACL drift, exportability/provider drift, SignTool
path/hash/version drift, missing Event Log sources, firewall default/rule/filter drift or a stopped
service. Installer `0.4.1` converts a verification failure to one fixed phase marker covering only
host validation, control ACLs, installed payload, deployment, service definitions, installation
ACLs, state directories, key ACLs, SignTool, component versions, firewall, Windows Time, Event Log sources,
service status or the final audit event. It never returns the underlying exception, local path or
operating-system diagnostic through the disposable controller result.
The control-ACL phase is further divided into only the control root, installed inventory, installed
deployment, installed release-digest and installed profile-set-lock files. The root reason is
further bounded to direct-path,
security-descriptor acquisition, owner/protection or exact-rule validation so a disposable rerun can
identify one closed boundary without returning the ACL, path, owner, access identities or native
diagnostic.
Rule objects are normalized once into only their SID, type, rights, inherited bit and applicable
inheritance/propagation flags, then compared with explicit loops. This avoids pipeline evaluation
ambiguity without changing the accepted rule set; a native property failure maps only to the fixed
root-rules reason.
Windows persists `Synchronize` automatically on an allow ACE. Installation-tree role ACEs are
therefore checked against the canonical persisted `ReadAndExecute, Synchronize` mask rather than
the pre-persistence shorthand. The setter immediately runs the same exact verifier before any later
service-start or key-use phase. A mismatch is bounded to only install root, Gateway/Worker/installer
root, or Gateway/Worker/installer files; paths, SIDs, masks and native diagnostics are never
returned.
Service dependency verification reads the registry property through the PSObject property
collection. `ArtifactSigningWorker` must depend on exactly `W32Time` for V2 or exactly `himds` and
`W32Time` for V3;
`ArtifactSigningGateway` must depend on exactly `ArtifactSigningWorker`. Dependency drift
maps only to fixed worker or gateway dependency phases, with no registry content returned.
The service image path is always stored with literal surrounding quotes. Installer `0.4.1`
launches the validated fixed `sc.exe` directly with `UseShellExecute=false`, canonical Windows
argument encoding, redirected/discarded output and a fixed timeout, so PowerShell cannot rewrite
embedded quotes. Windows CI creates randomized disabled service definitions and requires the same
exact quoted registry value under both PowerShell 7 and Windows PowerShell 5.1. Image-path drift
maps only to fixed worker or gateway image-path phases and never returns the installed path.

Installer `0.4.1` verifies the native persisted firewall representation immediately after writing
it and before service start. It requires the exact Domain/Private/Public deny-by-default profiles,
the closed enabled allow-rule names, profile scope, and one exact port, address, application and
service filter for each compiled rule. Failures expose only fixed categories for profiles, the rule
set, Gateway ingress, the selected provider's SignTool/Arc/DNS rules, time, or certificate status. The
underlying rule/filter values and operating-system diagnostics remain private. Its three canonical
ASCII control readers use explicit byte iteration and reject every byte above 127.
The fixed time rule is consumed only by `W32Time`. The installer invokes the direct, validated
`System32\w32tm.exe` path with `UseShellExecute=false`, a fixed argument grammar and a bounded
timeout. It persists only the deployment's exact IP addresses with the `0x8` NTP client flag,
requires the service to be automatic and running, and requires resynchronization before it starts
the signing services. Verification rejects peer, service-start, provider or running-state drift.
After a cold boot SCM starts `W32Time` before the delayed Worker. A running time service is not
proof that synchronization has completed. Also ensure the hypervisor RTC model and Windows time
zone agree; QEMU/Proxmox commonly presents a local-time RTC to Windows guests. A request whose
timestamp is still ahead of the appliance clock is rejected before key use; do not relax request
validity to hide clock drift. Wait for time convergence and repeat readiness and installed
verification.
The timestamp TCP connection is made by the direct, hash-pinned SignTool child, not by the Worker
service executable. Its allow rule therefore matches the configured absolute `signtool.exe` path,
service filter `Any`, and only the compiled relay address and port. Binding that rule to
`ArtifactSigning.Worker.exe` or `ArtifactSigningWorker` blocks the required child-process traffic;
permitting every program would unnecessarily broaden key-use egress.
For the managed provider, SignTool's process-scoped Internet rule still does not authorize the
Worker's independent post-signature `X509Chain` checks. The installer therefore creates two fixed
auto-resolved Windows Firewall dynamic keywords, `www.microsoft.com` and
`oneocsp.microsoft.com`, and one separate outbound rule restricted to
`ArtifactSigning.Worker.exe`, the `ArtifactSigningWorker` service, TCP ports 80/443, and those
keyword identifiers. The verifier rejects a changed FQDN, identifier, process, service, port or
rule set. Never replace these objects with a point-in-time IP list or an unrestricted Worker rule;
Microsoft certificate-status addressing may change while the certificate embeds stable FQDNs.
The signed readiness probe is a separate `GET /health/ready` made by
`ArtifactSigning.Worker.exe`. A second rule permits only that exact Worker executable and
`ArtifactSigningWorker` service to the same compiled relay address and port. It does not broaden
either process to another address or port.
Event Log source verification reads the three fixed registry keys through the .NET API with
environment expansion explicitly disabled. It requires exactly `EventMessageFile` as ExpandString
with the literal `%SystemRoot%\System32\EventCreate.exe` value and `TypesSupported` as DWORD 7,
and it runs immediately after registration. Failures expose only Gateway, Worker or installer.

The local verifier cannot authenticate to the mTLS API and therefore does not fake API readiness.
From one allowlisted client, verify `GET /v1/health/ready` through `artifact-signctl` transport
configuration and confirm the exact ready response. Then retrieve the auditor-only signed audit
head. A running service is not equivalent to readiness.

Prove separately that:

- an ordinary user cannot read ProgramData, configuration or key files;
- the Gateway SID cannot open the Authenticode or receipt key;
- the Worker SID cannot open the Gateway TLS key;
- a remote submitter cannot select a certificate, path, profile version or timestamp endpoint;
- the Worker owns no TCP/UDP listener; and
- outbound connections other than the exact relay, time and accepted revocation dependencies fail.

## Update and rollback

There is no network self-update. Build and review a new independently versioned package, stop
signing intake, stage it and run:

```powershell
install-artifact-signing-service.ps1 `
  -ExpectedReleaseHash <new-independent-sha256> `
  -Mode Update
```

Update first uses the staged installer to validate the protected control ACLs and an immutable
execution-trust ABI for the installed verifier: the install root, installer root, verifier and its
shared script must be direct, SYSTEM-owned, protected and non-writable by any identity other than
SYSTEM or Administrators. It then validates every installed payload byte against the installed
inventory before invoking the installed generation's own fixed verifier. A legitimate versioned
policy change is therefore compared against the policy that created the current generation without
trusting a writable or drifted script. Only after all checks pass does it stop services and preserve
exactly one protected prior service/configuration generation. It refuses to overwrite an existing
rollback generation.
The deployment control file may originate on read-only ISO media. Control-state replacement clears
only that exact protected destination's read-only attribute before overwrite, clears the copied
attribute again afterward, and then reapplies the exact SYSTEM/Administrators ACL with the other
control files.
If post-update verification fails:

```powershell
rollback-artifact-signing-service.ps1
```

The update first prepares the prior generation under a separate direct, protected
`rollback.next` directory and applies SYSTEM/Administrators-only ACLs to every copied directory and
file. It verifies the copied control ACLs, execution path, inventory and deployment before writing a
canonical protected transaction record and atomically renaming the complete directory to
`rollback`. Only that committed snapshot authorizes removal of the live generation. A preparation
interruption leaves the live generation authoritative; the next update keeps the exact stale
`rollback.next` as its recovery marker while it restarts and re-verifies the existing services,
then validates and removes only that direct tree before beginning again.

The staged incoming deployment requires installer `0.4.1`. The installed deployment and a copied
prior-generation checkpoint may use the current installer `0.4.1` or the explicitly reviewed
legacy compatibility versions `0.4.0` and `0.3.2`; no other legacy installer version is accepted. Missing or
unsupported profile-set evidence fails closed. The rollback generation retains and restores the
protected `installed-profile-set.lock` alongside the deployment, inventory and release digest. No
command-line, file or API input can add another accepted installer version.

Rollback uses the execution-trust and inventory gates before loading the prior generation's own
installer policy. Its transaction record advances monotonically through the current-generation
move, prior-generation move, control restoration and full native verification. It also records
whether update bytes were retained or no update directory existed when recovery began, so a power
loss immediately after removal of the old live directory is recoverable without inventing missing
evidence. Each move is restartable from its exact before-or-after filesystem layout; ambiguous or
missing retained evidence fails closed. After restoring exact bytes/configuration/control metadata,
rollback reapplies service/key/firewall policy, starts Worker then Gateway, and invokes the verifier
from the restored live path. When update bytes existed, they remain under the transaction's fixed
timestamped protected Program Files sibling for incident comparison. Remove them only after hash
evidence is retained and the incident is closed.

Each transaction-state transition writes an exact-ACL `rollback-state.next`, then uses Windows'
same-volume atomic replacement with the fixed protected `rollback-state.previous` backup path.
The new authority file is revalidated before that backup is removed. An interruption after atomic
replacement therefore leaves either the old canonical state plus `next`, or the new canonical state
plus `previous`; the next transition validates and removes only those exact recovery files.

Rollback never restores request state or private keys. Reconcile nonterminal requests and audit
heads before reopening intake.
Rollback reapplies the fixed time peers from the reviewed prior deployment before restarting the
signing services. Rolling back to installer `0.3.2` leaves that safe fixed Windows Time policy in
place because the legacy generation did not own host time configuration.

## Uninstall

```powershell
uninstall-artifact-signing-service.ps1 -Confirm
```

Uninstall removes service definitions, appliance firewall rules, Event Log sources and service
bytes. It deliberately preserves:

- every Local Machine certificate and private key;
- `%ProgramData%\ArtifactSigning` request, output, quarantine and audit state;
- installed/rollback evidence under `%ProgramData%\ArtifactSigningInstaller`; and
- deny-by-default Windows Firewall profile defaults; and
- the last reviewed fixed Windows Time configuration.

There is no installer option that deletes a key. Key destruction is a separate custody operation
requiring explicit identity, retention and recovery authorization.

## Windows Defender Application Control

WDAC/App Control is a deployment gate, not an installer side effect:

1. Start from Microsoft's signed-and-reputable base policy for the supported Windows build.
2. Add publisher/hash rules only for the exact accepted Gateway, Worker, PowerShell host,
   installer scripts, Windows SDK SignTool, .NET runtime/native extraction files and required
   Windows components.
3. Keep scripts constrained to the exact signed/hash-bound installer path. Do not allow arbitrary
   user-writable PowerShell content.
4. Deploy in audit mode on the disposable VM. Complete install, two restarts, reboot, signing,
   rollback and recovery while reviewing Code Integrity events.
5. Add only explained required events, regenerate evidence, then enforce on a fresh disposable VM.
6. Retain a tested out-of-band console recovery policy and clean pre-key snapshot before enforcing
   on the dedicated appliance.

Never disable WDAC, Defender, SmartScreen or firewall policy merely to make acceptance pass.
