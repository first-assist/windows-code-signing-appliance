# Security policy

This project controls access to code-signing keys and should be treated as security-critical
infrastructure. A passing build or source review is not an authorization to deploy, import a key,
or sign an artifact.

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue, discussion, pull request, test log, or
artifact. Use GitHub's private vulnerability reporting feature from the repository's **Security**
tab. If private reporting is unavailable, contact the repository owner through its published private
security channel and disclose only enough metadata to establish a secure exchange.

Do not include:

- real private keys, PFX/P12 files, passwords, tokens, or provider credentials;
- live client or certificate credentials;
- raw production configuration, state databases, archives, receipts, or logs;
- certificate contents or private-key storage identifiers; or
- exploit traffic against an appliance you do not own and have explicit permission to test.

Include the affected component/version, source commit, deployment mode, bounded reproduction steps,
expected security property, and observed safe result code. Redact local paths, network identities,
and certificate material.

## Security scope

High-impact areas include:

- bypass of mTLS, detached submitter signature, independent approval, or distinct-role policy;
- profile/package substitution or runtime code loading;
- signing a file not declared and validated by the compiled profile;
- Gateway access to the Authenticode or receipt key;
- a remotely reachable Worker interface;
- shell invocation or untrusted SignTool arguments, paths, certificates, or timestamp URLs;
- archive ambiguity, traversal, links, reparse points, alternate data streams, or partial output;
- failure to re-hash in Gateway, Worker, or client verification;
- fail-open timestamp, signer, revocation, audit, restart, or state behavior;
- recovery that resumes or publishes partially signed work;
- leakage of raw SignTool output, exception diagnostics, paths, or certificate contents; and
- release inventory, ACL, service, firewall, key-separation, or profile-set validation bypass.

General build failures, documentation errors, and feature requests may use the ordinary issue
tracker when they contain no sensitive environment information.

## Supported versions

Components are independently versioned and currently pre-1.0. Security fixes are applied to the
current source and released component version; old generated releases and consumer profile sets are
not automatically updated. Operators must retain exact release/profile evidence for historical
verification and plan complete-generation upgrades.

Until a repository release explicitly states otherwise, do not infer production support from the
presence of source code. The Microsoft Artifact Signing Worker provider is implemented, but its
provider-aware installer, egress policy, and native Azure Arc matrix remain acceptance-pending. The
implemented hardened installer track still uses a non-exportable Local Machine certificate and the
timestamp relay.

## Deployment requirements

Production deployment requires, at minimum:

- a new dedicated Windows machine or VM;
- a non-exportable machine-scoped signing key or separately reviewed managed/HSM provider;
- separate Gateway TLS, receipt, signing, submitter, and approver identities;
- a private mTLS listener and exact deny-by-default network policy;
- an independently built and reviewed static consumer profile package;
- online revocation and fail-closed timestamping;
- generated-key native Windows and installer acceptance; and
- an independent release inventory authorization.

Never install onto an existing signer or acceptance template, copy private-key state, or snapshot a
live software key unless encrypted snapshot/key custody and recovery have been explicitly designed
and accepted.

## Secret handling

No real credential belongs in this repository, an issue, CI fixture, release package, or sample.
Tests generate disposable identities. Examples use placeholders and reserved names/addresses. If a
secret is accidentally committed, stop using it and rotate or revoke it; deleting the current file
does not remove it from Git history.

## Security changes

Changes to protocol contracts, archive handling, identity/trust policy, profile ABI, key access,
SignTool execution, timestamping, durable state, audit, ACLs, firewall, installer, recovery, or
error projection require explicit security review and adversarial tests. Changed distributable
bytes receive a new component version in the same commit.
