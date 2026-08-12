# Client operations

`artifact-signctl` is the cross-platform client for build agents, independent approvers, and
offline result verification. It talks only to the private HTTPS Gateway; it never contacts Worker,
Windows certificate stores on the appliance, SignTool, the appliance filesystem, the package
composer, a timestamp authority, or signing-provider credentials.

The CLI contains the exact statically compiled profile package set. Before submission it discovers
visible profiles and requires the server's profile-set and package binding to equal its own. It then
validates the local bundle through the selected profile. Gateway and Worker repeat the archive,
digest, signature, authorization, and profile checks independently.

## Installation and matching release

Use the CLI from the same sealed release generation as the appliance/profile set. Do not install a
generic CLI and point it at arbitrary service versions. Retain old matching CLI releases for
historical result verification.

On Linux, install the executable in an administrator-owned non-writable location and keep each
identity/configuration directory owner-only. On Windows, use a protected installation directory and
prefer a non-exportable Current User certificate-store identity.

## Client configuration

Select a configuration with `--config <absolute-path>`. If omitted, the CLI checks
`ARTIFACT_SIGNING_CONFIG` and then the operating system Application Data path
`artifact-signing/client.json`.

Use separate owner-only submitter and approver configurations. A configuration contains:

- private HTTPS Gateway URI;
- exact Gateway TLS certificate and SPKI SHA-256 pins;
- one PEM-file or Windows Current User store client identity;
- public trust and expected SPKI for request/approval verification; and
- public trust and expected SPKI for Worker receipt verification.

Linux private keys and password/reason files must be direct, single-link `0600` files outside
workspaces. Do not place private keys, PFX files, passwords, tokens, or certificates with private
keys in arguments, environment variables, repositories, archives, or logs. Production requires
online revocation and distinct submitter/approver identities.

See [configuration reference](configuration-reference.md#cli-configuration-v1) for the exact
schema and provider rules.

## Commands

Every command accepts optional `--config <path>`.

### Verify the installed client version

```bash
artifact-signctl --version
```

This command requires no configuration or identity and emits exactly one invariant semantic
version line. Deployment automation should pin both this exact output and the executable SHA-256;
the version alone is not an integrity check.

### Discover profiles

```bash
artifact-signctl profiles list --config /owner-only/submitter.json
```

Discovery returns only profiles authorized to the mTLS identity and includes exact profile,
package, assembly, descriptor, and package-set binding. Compare it with retained release evidence
before the first request and after every update.

### Submit

```bash
artifact-signctl submit --config /owner-only/submitter.json \
  --project example-project \
  --profile ExampleBundleV1 \
  --bundle /owner-only/unsigned-bundle \
  --source-repository example/repository \
  --source-commit 0123456789abcdef0123456789abcdef01234567 \
  --release-version 1.2.3
```

`--bundle` is a directory containing exactly the profile-declared leaf files. The CLI validates it,
creates the closed uncompressed archive and canonical request, and signs the request with the client
identity. The command prints only the opaque request UUID, public request digest, and coarse state.

Retain the UUID and digest. Do not approve based only on the submitter's terminal output or a copied
display name.

### Inspect status

```bash
artifact-signctl status --config /owner-only/submitter.json \
  --request 00000000-0000-0000-0000-000000000000
```

Status returns bounded state and public evidence appropriate to the authenticated role. It never
returns raw service, filesystem, certificate, exception, or SignTool diagnostics.

### Review a pending request

An approver can obtain a read-only, trust-verified summary before presenting an operator decision:

```bash
artifact-signctl review --config /owner-only/approver.json \
  --request 00000000-0000-0000-0000-000000000000 \
  --expected-digest <independently-obtained-lowercase-sha256> \
  --format json
```

The command requires an independently supplied digest. It verifies pending status, approver
authorization, the closed review archive, submitter CMS, request/status binding, time bounds, and
the exact digest without changing request state. `--format text` is the terminal default;
`--format json` emits the stable `ArtifactSigningReviewSummaryV1` integration contract.

Use [approval client integration](approval-client-integration.md) when placing an operator UI or
release-management service in front of this command. Browser code must not parse review archives,
construct approval CMS, or hold the approver identity.

### Approve or reject

Create a short owner-only reason file after independently reviewing source, build, bundle, request,
and digest evidence.

```bash
artifact-signctl approve --config /owner-only/approver.json \
  --request 00000000-0000-0000-0000-000000000000 \
  --reason-file /owner-only/approval-reason.txt \
  --expected-digest <independently-obtained-lowercase-sha256>
```

Or reject:

```bash
artifact-signctl reject --config /owner-only/approver.json \
  --request 00000000-0000-0000-0000-000000000000 \
  --reason-file /owner-only/rejection-reason.txt \
  --expected-digest <independently-obtained-lowercase-sha256>
```

`--expected-digest` is optional in the command grammar for compatibility but should always be
supplied by a production approval ceremony. Obtain it through a channel independent of the pending
request lookup and compare it before signing approval.

### Wait

```bash
artifact-signctl wait --config /owner-only/submitter.json \
  --request 00000000-0000-0000-0000-000000000000 \
  --timeout-seconds 900
```

The timeout is 1 through 1800 seconds and defaults to 900. A client timeout does not cancel or alter
the durable appliance request.

### Cancel

```bash
artifact-signctl cancel --config /owner-only/submitter.json \
  --request 00000000-0000-0000-0000-000000000000
```

Cancellation is subject to authenticated role and explicit state transitions. It cannot recall a
key operation already committed or rewrite a terminal state.

### Download

```bash
artifact-signctl download --config /owner-only/submitter.json \
  --request 00000000-0000-0000-0000-000000000000 \
  --output /owner-only/signed-result.tar
```

The output path must not already exist. Before atomically creating it, the CLI verifies the detached
receipt, exact result inventory, returned hashes, request binding, and profile-finalized output. It
does not expose partially downloaded bytes at the requested path.

### Verify an existing result

```bash
artifact-signctl verify --config /owner-only/submitter.json \
  --result /owner-only/signed-result.tar
```

Standalone verification uses the configuration's receipt trust and the CLI's compiled profile set.
Use the historical CLI/profile release and retained package-set evidence that correspond to the
receipt. A current CLI must not silently reinterpret an old profile version with different bytes.

## Recommended release flow

1. Submitter builds in a clean, reproducible process and prepares only the profile-declared bundle.
2. Submitter runs `profiles list`, checks exact package binding, then runs `submit`.
3. Submitter records UUID/digest and sends review material through an authenticated independent
   channel.
4. Approver runs `review --expected-digest`, then checks the verified release and artifact summary.
5. Approver writes a bounded reason and runs `approve --expected-digest`; otherwise runs `reject`.
6. Submitter runs `wait`, then `download` to a new protected file.
7. Submitter runs `verify` independently and validates consumer release/publishing rules.
8. The consuming project retains the complete public evidence set before publishing artifacts.

The appliance signs; it does not decide that a release should be published and does not upload the
result to a release system.

## Evidence retention

Keep:

- request UUID and exact request digest;
- source repository, full source commit, and release version;
- submitted unsigned artifact hashes and build evidence;
- approver identity, signed approval, reason, and independently verified digest;
- profile ID/version and complete discovery response;
- profile package manifest, assembly/package/descriptor digests, and `profile-set.lock`;
- appliance source commit and release inventory digest;
- signed result archive, receipt, and receipt digest; and
- the matching CLI/profile release needed for later verification.

Receipt V1 retains profile identity/version but does not embed package or package-set digests. That
is why package-set discovery and release evidence must be retained separately.

## Failure handling

Do not loop retries on an uncertain signing, timestamp, revocation, readiness, audit, or state
failure. Record the bounded result code, stop new intake when required by the operations runbook, and
have an operator inspect protected local diagnostics. Never request raw SignTool output or weaken
client verification to recover availability.

If discovery binding changes unexpectedly, stop before submission. If download or standalone
verification fails, do not publish any extracted artifact even if Windows displays an embedded
signature.
