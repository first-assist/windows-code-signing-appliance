# Identity operations

Identity separation prevents a network-facing compromise or one client credential from becoming a
signing authorization. Production deployments require independently issued and operated identities;
do not combine roles merely because one certificate has multiple EKUs.

## Identity inventory

| Identity | Private key location | Used by | Purpose |
| --- | --- | --- | --- |
| Gateway TLS | Windows `LocalMachine\My` | Gateway only | Private HTTPS server authentication |
| Receipt/audit signer | Windows `LocalMachine\My` | Worker only | Detached result receipts and audit anchors |
| Authenticode signer | Windows `LocalMachine\My` | Worker/SignTool only | Embedded Windows code signatures |
| Submitter client | Client-controlled store or owner-only PEM | One submitter role | mTLS and detached request signature |
| Approver client | Separate client-controlled store or PEM | One approver role | mTLS and exact-digest approval/rejection signature |
| Auditor client | Client-controlled public/API identity | Optional auditor | Read-only authorized evidence access |
| Timestamp authority | Public certificate chain only | SignTool verification | RFC 3161 token validation |

Production submitter and approver identities must have different subject-public-key-info digests.
Gateway TLS, receipt, and Authenticode certificates must not share a private key.

## Windows private-key requirements

Gateway TLS, receipt, and Authenticode identities resolve by exact uppercase thumbprint from the
Local Machine personal store. Each must be unique, currently valid, have the required EKU, and have
an accessible RSA CNG machine key with export policy `None`.

The installer rejects missing, ambiguous, exportable, ephemeral, non-CNG, wrong-scope, or shared
private-key state. It never exports a key. After resolving Windows service SIDs, it applies:

- Gateway access to the Gateway TLS key only;
- Worker access to receipt and Authenticode keys only; and
- no Authenticode or receipt permission for Gateway.

Do not grant a broader user, service group, administrator helper service, web process, or build agent
access to make enrollment or troubleshooting easier. If the approved certificate provider cannot
produce compatible non-exportable machine CNG state, stop and design a separate provider track.

## Certificate purposes

- Gateway TLS requires Server Authentication (`1.3.6.1.5.5.7.3.1`) and a subject alternative name
  matching the private service URI used by clients.
- Submitter and approver mTLS certificates require Client Authentication
  (`1.3.6.1.5.5.7.3.2`). Their detached CMS signing trust is pinned to the expected SPKI and the
  configured EKU.
- Authenticode certificates require Code Signing (`1.3.6.1.5.5.7.3.3`). Signed output is checked
  for SHA-256 Authenticode and RFC 3161 timestamp evidence.
- The receipt signer uses the exact EKU selected in Gateway, Worker, and CLI trust configuration.
  Choose a purpose-specific issuance policy rather than reusing the Authenticode certificate.
- Timestamp certificates are validated for Time Stamping (`1.3.6.1.5.5.7.3.8`) through the
  timestamp token chain.

Treat OIDs and issuance templates as reviewed policy. Do not copy an example OID without confirming
the intended identity role.

## Public trust installation

Install only the public roots and intermediates needed by configured policies. Gateway/Worker trust
uses exact store thumbprints; CLI trust uses exact public certificate paths. Every trust policy also
pins the expected signer SPKI and required EKU.

Production uses online revocation with a bounded retrieval timeout. Identify certificate-status
network destinations before deny-by-default egress is applied. If status is unavailable or
uncertain, readiness/signing fails closed; do not switch to offline/no-check verification as an
availability workaround.

Do not put certificate contents in ordinary logs or evidence. Record public thumbprints, SPKI
SHA-256, issuer/policy identifiers, validity, EKUs, and independently approved trust inventory.

## Client key handling

Linux automation may use a public certificate and private key in separate absolute direct files.
Make the directory owner-only and each private key/password/reason file a single-link `0600` file.
Do not place the password itself in configuration, environment variables, arguments, CI variables
that print into logs, or the source workspace.

Windows clients may select one non-exportable Current User store certificate by exact thumbprint.
The identity must resolve uniquely and be usable by only the intended submitter or approver account.

Keep mTLS and detached CMS use bound to the same configured client identity. A display name, project
name, or certificate subject is not authorization.

## Provisioning sequence

1. Define each role, issuance policy, EKU, trust roots, lifetime, revocation method, and custodian.
2. Issue client identities to separate submitter and approver owners.
3. On the clean dedicated Windows appliance, enroll Gateway TLS, receipt, and Authenticode machine
   identities without an export operation.
4. Record and independently verify public thumbprints and SPKI digests.
5. Install only reviewed public trust.
6. Bind exact identities into Gateway/Worker templates, deployment manifest, and client
   configurations.
7. Build the sealed release and let the installer apply service-SID key permissions.
8. Verify key separation before the first end-to-end generated or real signing request.

The installer is not an enrollment tool. Certificate issuance/import is an operator-controlled
prerequisite and must not create a PFX transfer path.

## Rotation

Identity rotation is a reviewed full release:

1. close Gateway intake and terminally resolve or quarantine nonterminal requests;
2. retain external audit heads, package-set/release evidence, and historical receipt trust;
3. issue and validate the new public identity through the approved channel;
4. add only the minimum bounded old/new trust overlap needed by the protocol;
5. build, authorize, install, and verify a complete new generation;
6. prove new, old, cross-role, revoked, and unauthorized behavior in disposable acceptance;
7. move clients and confirm exact discovery/package binding;
8. remove old authorization in another complete reviewed generation; and
9. revoke/retire old credentials while retaining public evidence needed for historical receipts.

Do not change a thumbprint in place, share a key during overlap, or reinterpret an existing profile
to accept a different signer without a profile version review.

## Compromise or uncertainty

On suspected client, Gateway TLS, receipt, Authenticode, CA, or provider compromise:

- stop Gateway intake;
- preserve external audit heads and protected evidence;
- revoke the affected identity through its authority;
- do not export or copy the key for investigation;
- do not delete quarantine or edit request state;
- determine the exact affected request/release interval; and
- recover through a new reviewed identity and complete appliance generation.

Revocation uncertainty itself is a closed failure. Follow the [recovery runbook](recovery-runbook.md)
and report product vulnerabilities privately under [SECURITY.md](../SECURITY.md).
