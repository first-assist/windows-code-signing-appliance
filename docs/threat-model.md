# Threat model

The protected asset is the non-exportable Authenticode key. The Gateway is network reachable only
on a private mTLS interface and cannot access that key. The Worker has no listener and signs only
Worker-owned exact bytes after independent request, approval, archive, policy, package-set, and
profile validation.

Threats include malicious submitters, compromised client identities, archive ambiguity, replay,
profile/package substitution, dependency confusion, signing-tool drift, timestamp/revocation
failure, filesystem links/ACL drift, service restart ambiguity, and installer rollback. Controls
are closed archive parsing, exact CMS/mTLS identities, expiry/nonces, distinct approval, static
profile composition, canonical package manifests/locks, release inventory, configuration V2 digest
binding, direct-file/ACL checks, one signing lease, quarantine, signed audit anchors, and fail-closed
Windows verification.

Administrators are trusted to install a reviewed release, not to use a network API to extend it.
Runtime plugins would execute new code in the key-bearing Worker and are therefore out of scope.
