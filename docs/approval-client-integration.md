# Approval client integration

An operator portal may present signing requests and collect a human approval, but it must use the
matching `artifact-signctl` release as its trust and protocol boundary. Browser code must not hold an
approver private key, parse the appliance review archive, construct CMS, or call the Gateway
approval endpoint directly.

This integration is deliberately narrower than artifact hosting, publication, or deployment. An
approval authorizes one exact request digest to enter signing. It does not authorize publishing or
deploying the returned files.

## Trust boundary

Use three distinct identities and execution contexts:

1. the build or submission identity prepares and submits the closed artifact bundle;
2. an authenticated human operator authorizes or rejects the exact pending request; and
3. a protected approval backend owns the approver CLI configuration and identity.

The submitter must not be able to invoke the protected approval backend. The browser receives only
bounded public review data and the decision result. It never receives a client configuration,
certificate with private key, password, reason-file path, raw CMS, service command line, or raw
Gateway response.

On Windows, prefer a non-exportable Current User certificate-store identity owned by the dedicated
approval service account. On Linux, keep the PEM identity, configuration, and transient reason file
in owner-only directories outside source and artifact workspaces. A hardware-backed identity with
operator presence is stronger when the client platform supports it.

## Read-only review

The submitter records the UUID and digest printed by `submit` in the release system. Transfer that
digest to the approval system through an authenticated channel independent of the Gateway review
lookup. The approval backend then runs:

```bash
artifact-signctl review --config /owner-only/approver.json \
  --request 00000000-0000-0000-0000-000000000000 \
  --expected-digest <independently-obtained-lowercase-sha256> \
  --format json
```

`review` is read-only. It:

1. authenticates to the Gateway with the approver mTLS identity;
2. requires the request to be `PendingApproval` and authorized for that approver;
3. downloads the closed review archive;
4. verifies the submitter CMS under the configured trust policy;
5. recomputes the request digest;
6. binds every request identity field to the current Gateway status;
7. checks request time and expiry; and
8. compares the result with `--expected-digest` in constant time.

Any failed check produces a nonzero exit and no review JSON. The command does not create an
approval, reserve the request, or change appliance state.

`--format text` is the default for a terminal. `--format json` emits exactly one compact JSON object
followed by a newline. The stable schema is:

```json
{
  "Format": "ArtifactSigningReviewSummaryV1",
  "RequestId": "00000000-0000-0000-0000-000000000000",
  "RequestDigest": "0000000000000000000000000000000000000000000000000000000000000000",
  "State": "PendingApproval",
  "CanApprove": true,
  "ProjectId": "example-project",
  "ProfileId": "ExampleBundleV1",
  "ProfileVersion": 1,
  "SourceRepository": "example/repository",
  "SourceCommit": "0123456789abcdef0123456789abcdef01234567",
  "ReleaseVersion": "1.2.3",
  "SignerPolicyId": "ExamplePublicTrustV1",
  "TimestampPolicyId": "ExampleRfc3161V1",
  "RequestedAt": "2026-01-02T03:04:05Z",
  "ExpiresAt": "2026-01-02T03:19:05Z",
  "CreatedAt": "2026-01-02T03:04:06Z",
  "UpdatedAt": "2026-01-02T03:04:07Z",
  "SubmitterSpkiSha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "Artifacts": [
    {
      "Role": "Agent",
      "File": "example.exe",
      "Size": 1234,
      "Sha256": "0000000000000000000000000000000000000000000000000000000000000000"
    }
  ]
}
```

Timestamps are whole-second UTC. Arrays retain canonical request order. Unknown formats or fields
must fail closed in the integrating application; do not silently accept a future schema. The
integrator should cap captured standard output and require exactly one JSON value with no trailing
content other than whitespace.

## Operator decision

Show the verified review rather than values copied from an untrusted browser form. At minimum, the
operator view should make these facts prominent:

- test or production environment classification maintained by the consuming release system;
- project, release version, source repository, and full commit;
- appliance profile ID and version;
- signer and timestamp policy aliases;
- every artifact name, role, size, and SHA-256;
- request expiry and exact digest; and
- a statement that signing approval does not publish or deploy the result.

Require a fresh privileged operator session, an explicit approve or reject action, and a bounded
reason. Production interfaces should require release-specific confirmation and must prevent the
requesting automation identity from satisfying the human approval check.

After the human confirms, create a new owner-only reason file and invoke the matching decision
command without a shell:

```bash
artifact-signctl approve --config /owner-only/approver.json \
  --request 00000000-0000-0000-0000-000000000000 \
  --reason-file /owner-only/transient-reason.txt \
  --expected-digest <same-independently-obtained-lowercase-sha256>
```

Use `reject` with the same arguments to reject. The decision command intentionally re-fetches
status and the signed review, repeats all review checks, compares the digest again, and then creates
a five-minute `ArtifactSigningApprovalV1` CMS. The Gateway performs its own authorization,
signature, digest, expiry, distinct-identity, and compare-and-swap checks. A stale or concurrently
changed request therefore fails rather than receiving an obsolete decision.

When `--expected-digest` is supplied, `approve` and `reject` do not prompt on standard input. The
integrating portal owns the human confirmation step and must complete it before launching the
decision command.

## Process execution rules

The approval backend must:

- use an administrator-installed, hash/version-pinned absolute CLI path from the matching appliance
  profile generation;
- invoke the executable directly with an argument array and `UseShellExecute=false` or the platform
  equivalent;
- accept only a parsed canonical UUID, lowercase SHA-256, enumerated decision, and bounded UTF-8
  reason from application code;
- use fixed deployment-owned configuration and working-directory paths;
- create the reason file with owner-only permissions, verify those permissions, and remove it after
  the child process exits;
- apply bounded output capture, execution timeout, cancellation, and single-flight protection per
  request;
- treat every nonzero exit, malformed JSON, digest mismatch, unknown state, timeout, or ambiguous
  response as a failed decision;
- return only a bounded application error to the browser; and
- record the authenticated operator, review digest, decision, reason, and outcome in append-only
  release-system audit history.

Do not pass a private key, password, certificate bytes, configuration JSON, arbitrary path, command
fragment, provider selector, timestamp URL, or signing option from the browser. Do not log child
process arguments when they include protected local paths.

## Artifact and history systems

The appliance is not an artifact repository. A consuming release system may retain unsigned input,
signed results, receipts, manifests, build evidence, and historical downloads in its own immutable
object storage. Keep that storage digest-bound and independently authorize downloads. Never use an
artifact-storage record as authority to alter the appliance profile, choose a certificate, or
bypass exact-digest approval.

Model signing approval, successful signature verification, publication approval, publication, and
deployment as separate state transitions and permissions. Promote the same verified bytes between
stages; do not rebuild a release after approval merely to move it to another environment.

## Failure and recovery

Refreshing status or repeating a read-only `review` is safe. Do not blindly repeat a decision after
an uncertain response: fetch bounded status first. If the request is already `Approved`, `Signing`,
or terminal, preserve the original decision evidence and follow the consuming system's
reconciliation procedure.

Never weaken trust, revocation, digest, distinct-identity, expiry, or profile checks to recover
availability. Protected appliance diagnostics remain an operator concern and must not be projected
through the approval portal.
