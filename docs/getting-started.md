# Getting started

This guide describes a dedicated Windows signing appliance using either Microsoft Artifact Signing
through Azure Arc managed identity or a non-exportable Local Machine Authenticode key with a
separate Linux timestamp relay. The appliance is hypervisor-independent: a physical Windows host,
ordinary VM, private-cloud VM, or public-cloud VM can supply the required controls. Proxmox is not
required.

This is an operator integration guide, not a copy-and-paste production recipe. Certificate
issuance, network addresses, trust roots, revocation endpoints, time sources, profile rules, and
release authorization are specific to each environment and require independent review.

## Before you begin

You need:

- a source workstation with Git, the .NET SDK pinned by `global.json`, and PowerShell 7;
- a new dedicated Windows machine or VM with an isolated private address;
- an x64 Windows SDK SignTool installed beneath its normal Windows Kits location;
- an enterprise or reviewed certificate issuance process for Gateway, receipt, and client identities;
- for Microsoft Artifact Signing, an Arc-enabled Windows host, one profile-scoped managed-identity
  role, the reviewed Microsoft client tools, and the declared shared .NET runtime;
- for Local Machine signing, a non-exportable Authenticode identity and one separate Linux machine,
  VM, or container for the timestamp relay;
- a private network/firewall capable of exact address and port rules;
- fixed Windows Time peer addresses;
- two people or automation identities for submit and approve roles; and
- an application-specific compiled profile package.

Do not begin on an existing signer, developer workstation, domain controller, build agent, or
virtualization management host. Do not generate or import a production key until source,
configuration, profile, installer, and disposable generated-key acceptance gates pass.

## 1. Review the trust design

Read:

1. [architecture and trust boundaries](architecture.md);
2. [threat model](threat-model.md);
3. [profile authoring](profile-authoring.md); and
4. [Windows installation and hardening](windows-installation-hardening.md).

Record the planned trust boundaries before choosing addresses or certificates. In particular,
confirm that Gateway and Worker will run as separate virtual service identities and that only the
Worker will receive private-key permissions.

## 2. Establish the network layout

Allocate exact addresses for:

- the Windows Gateway listener;
- each submitting and approving client allowed through the firewall;
- the Linux timestamp relay when using the Local Machine provider;
- DNS resolvers and the Arc/managed-signing upstream policy when using Microsoft Artifact Signing;
- certificate-status endpoints required for online revocation; and
- Windows Time peers.

The installer applies deny-by-default outbound and inbound policy. The Local Machine track creates
separate exact-address rules for Worker relay readiness and the hash-pinned SignTool timestamp
request. The managed track creates only exact process/service-scoped SignTool, Arc, and DNS rules;
it does not claim that Windows Firewall enforces Microsoft's changing FQDN/service-tag policy.
Follow the managed-provider guide for the required upstream network contract. Do not use a subnet
where an exact host list is accepted.

The checked-in relay JSON and nftables files use placeholder networks and an `.invalid` hostname.
They cannot be used unchanged.

## 3. Prepare a disposable acceptance machine

Before touching a real signing key, create a disposable Windows test machine matching the target
operating system, Windows SDK, architecture, filesystem, and network policy. Apply updates, remove
general-purpose tooling and media, and create a clean pre-key recovery point.

Run only generated test identities. Acceptance must prove:

- installation and exact release inventory;
- service account and key separation;
- direct-file, ACL, firewall, time, and SignTool policy;
- Gateway/Worker startup order and readiness;
- an end-to-end submit/approve/sign/download/verify operation;
- independent service restarts and a cold reboot;
- full-generation update and rollback;
- timestamp and revocation outage behavior;
- archive, state, package-set, configuration, and filesystem tamper rejection; and
- quarantine rather than resume after ambiguous signing.

Destroy the disposable machine and its generated key state after the run. See
[development and testing](development.md).

## 4. Build a consumer profile package

Create the profile in the consuming project's repository. Reference the reviewed
`ArtifactSigning.Profiles` ABI version, implement one or more static singleton `ISigningProfile`
types, and test exact input and output semantics.

Package one managed assembly beside `profile-package.txt`:

```text
Format=ArtifactSigningProfilePackageV1
PackageId=Example.Profile.Package
PackageVersion=1.0.0
AssemblyFile=Example.Profile.Package.dll
AssemblySha256=<lowercase-sha256>
Profile=ExampleBundleV1|1|Example.Profile.Package.ExampleBundleV1
```

The package directory contains only those declared files. Any rule or byte change receives a new
package version; any change in accepted input, output meaning, or security decision also receives a
new profile version. Review the exact assembly hash and manifest outside the build channel.

The synthetic `tests/ArtifactSigning.TestProfile` project demonstrates a strict multi-file profile,
portable executable inspection, deterministic finalization, and signed-output validation. It is
test code and must not be installed as a production policy.

## 5. Provision identities

Production requires separate:

- Gateway TLS certificate and private key;
- receipt/audit signing certificate and private key;
- either a Local Machine Authenticode certificate/private key or an Artifact Signing
  certificate-profile-scoped managed identity;
- submitter client certificate and private key;
- approver client certificate and private key; and
- optional auditor client certificates.

Gateway TLS and receipt private keys reside in `LocalMachine\My`; receipt keys must be
non-exportable CNG machine keys. With the Local Machine provider, the Authenticode key also resides
there and must be a distinct non-exportable CNG machine key. With Microsoft Artifact Signing, no
Authenticode private key is installed: the Worker alone receives local access to the Arc machine
identity and Azure RBAC is scoped to one certificate profile. The installer resolves identities,
rejects ambiguous or unsuitable state, and applies service-SID key access. It does not enroll Arc,
create role assignments, issue/import/export/renew certificates, or back up keys.

Client private keys remain on client systems. Linux clients use owner-only direct PEM files;
Windows clients may use a uniquely resolved non-exportable Current User certificate-store key.
Install only the required public roots and intermediates. Production trust uses online revocation
and does not use leaf-certificate pins as a substitute for PKI validation.

Follow [identity operations](identity-operations.md) for requirements and rotation.

## 6. Prepare the signing provider

For Microsoft Artifact Signing, follow [Microsoft Artifact Signing](microsoft-artifact-signing.md):
Arc-enable the dedicated Windows host, assign its system identity at one test profile only, acquire
and verify the complete x64 client-tools directory off-appliance, and record the stable publisher
subject digest, subscriber EKU, and root from an independently correlated test signature. Do not
pin a rotating leaf or allow a developer credential fallback.

For the Local Machine provider, deploy the timestamp relay as follows.

Publish `ArtifactSigning.TimestampRelay` for the Linux target, create a non-interactive service
account, and install the binary beneath a root-owned non-writable directory. Create a strict
configuration from `deploy/linux/timestamp-relay/timestamp-relay.example.json` and merge reviewed
nftables equivalents from the adjacent example into the host's firewall.

The production relay configuration contains:

- one private bind address and non-privileged port;
- one to sixteen exact private Windows client addresses;
- one canonical HTTPS upstream URL;
- one to four exact upstream destination addresses; and
- bounded connect, total, and rate limits.

If the public authority changes address, deploy a reviewed configuration and firewall update. Do
not silently follow DNS-selected destinations or widen egress. Complete instructions are in
[timestamp relay operations](timestamp-relay-operations.md).

## 7. Create Gateway and Worker templates

Create complete strict JSON configuration templates in a protected review directory. They are
offline release inputs, not repository defaults. The Gateway template defines:

- deployment mode, service SIDs, profile-set binding, listener, and TLS identity;
- project/profile authorization;
- exact submitter and approver mTLS identities;
- submitter, approver, receipt, and optional auditor trust; and
- production dual-control policy.

The Worker template defines:

- deployment mode, service SIDs, and profile-set binding;
- the same project/profile signature authorization policy;
- fixed signer/timestamp policy aliases;
- exact SignTool path, SHA-256, four-part version, timeout, and revocation policy;
- either the Local Machine Authenticode identity/relay policy or the fixed managed provider,
  account, profile, Dlib inventory, publisher policy, and managed-identity-only credential path; and
- receipt identity and trust.

The installer substitutes only its fixed machine placeholders. It rejects any extra placeholder.
Use the [configuration reference](configuration-reference.md) and the strict configuration unit
tests as executable schema examples. Never place a private key, password, PFX, provider secret, or
certificate contents in either template.

## 8. Create `deployment.txt`

Create the canonical ASCII/LF deployment manifest documented in
[Windows installation and hardening](windows-installation-hardening.md). Use
`ArtifactSigningInstallerDeploymentV2` only for Local Machine signing and
`ArtifactSigningInstallerDeploymentV3` only for Microsoft Artifact Signing. It binds the source
commit, component versions, profile-set digest, fixed network addresses, public certificate
thumbprints, SignTool path/hash/version, and exact provider/firewall/time policy. V3 additionally
binds the complete managed client-tools inventory and stable publisher policy.

The `SourceCommit` must be the full lowercase commit at the clean builder worktree's `HEAD`.
Component versions must equal the project versions being built. Values are data, not shell syntax;
do not quote, interpolate, or add comments.

## 9. Build and authorize the release

Run `installer/Build-ArtifactSigningRelease.ps1` with the two templates, deployment manifest, one
or more profile package manifests, and a new output directory. For deployment V3, also supply
`-MicrosoftArtifactSigningClientToolsDirectory` with the complete reviewed x64 directory. The
script verifies the clean source commit, composes profiles offline, publishes self-contained
binaries, removes debug symbols, and creates a closed inventory.

Independently record and approve:

- source commit;
- profile manifest and assembly digest;
- generated package-set lock and digest;
- deployment manifest;
- exact SignTool hash and version; and
- final release inventory digest.

Transfer the closed release through a controlled channel. The independent authorization is the
inventory digest, never a filename, path, VM name, or operator statement.

## 10. Install and verify Windows

Use an elevated local or secured out-of-band console. Stage the release with the independently
supplied digest, then invoke the staged installer in `Install` mode. The installer installs exact
bytes, configures virtual service identities, applies exact ACL and private-key permissions,
registers fixed event sources, configures deny-by-default firewall and Windows Time, verifies the
entire installation, and starts Worker before Gateway.

Run the installed verifier immediately, after separate service restarts, and after a cold reboot.
Also verify profile discovery from a client built with the identical package set. Any failure keeps
intake closed and returns to the disposable acceptance or reviewed rollback process.

## 11. Configure submitter and approver clients

Distribute the matching CLI release and public trust through a protected channel. Create separate
owner-only `ArtifactSigningCliConfigurationV1` files. Pin the Gateway certificate SHA-256 and SPKI,
configure the correct client identity provider, and install trust paths for request and receipt
signers.

Run `artifact-signctl profiles list` from each role. It must show only authorized profiles and the
expected profile-set/package binding. Do not submit if discovery differs from retained release
evidence.

## 12. Complete the first signing ceremony

The submitter validates and submits the exact unsigned bundle, retains the returned UUID and digest,
and transfers the digest to the approver through an independent authenticated channel. The approver
reviews the source and artifact evidence, supplies the expected digest, and signs approval. The
submitter waits, downloads to a new file, and runs standalone verification.

Retain the result archive, request and receipt digests, profile identity, discovery response,
package manifest, package-set lock, appliance inventory, and matching CLI release as protected
release evidence. Receipt V1 does not embed the package digest, so historical verification depends
on retaining the exact package-set evidence.

## Ongoing operation

Close intake for every binary, configuration, identity, SignTool, timestamp, firewall, or profile
change. Drain or terminally resolve requests, retain external audit heads, deploy a complete new
generation, repeat installed verification and relevant acceptance, and confirm exact discovery
binding before reopening.

Start Worker before Gateway. Stop Gateway before Worker. Never modify protected state by hand,
resume quarantined work, broaden a rule to regain availability, or export a signing key for
troubleshooting.
