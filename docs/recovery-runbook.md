# Signing appliance recovery

On readiness loss, ambiguity, audit discontinuity, package-set mismatch, installer failure, or
identity compromise, stop Gateway intake, retain the last external audit heads and release evidence,
and do not edit state, delete quarantine, loosen ACLs, export a key, or retry partial signing.

For `RequestExpired` immediately after restart, first treat clock state as unready. Verify the
fixed `W32Time` policy and appliance installation; do not widen request validity or alter signed
timestamps. Installer `0.3.2` can reapply the exact deployment peers during a reviewed full update
or rollback when restoring that explicitly supported legacy generation; installer `0.4.1` owns the
current policy. Reopen intake only after synchronization, installed verification and exact profile
discovery succeed.

For Microsoft Artifact Signing, also require `himds` readiness, exact Worker-only membership in
`Hybrid Agent Extension Applications`, the pinned client-tools inventory, and the declared Arc and
SignTool firewall rules. Online post-signature verification additionally requires the two sealed
Microsoft certificate-status FQDN keywords and their exact Worker-only rule. Do not substitute an
IP snapshot, an unrestricted Worker Internet rule, an Azure CLI login, interactive credential, service
principal secret, unpinned Dlib, or broad all-program egress to recover availability.

Worker startup must reconcile schema, audit chain, durable state, package set, and filesystem
relationships. Interrupted signing is quarantined and never resumed. Start Worker alone; only after
it publishes a fresh valid anchor may Gateway start.

For configuration, binary, profile-set, ACL, or firewall drift, use the exact installed verifier
and a reviewed full-generation update or rollback. Rollback restores prior bytes, configuration,
profile-set lock, and policies, not request metadata or keys. Preserve old package manifests,
assembly hashes, locks, inventories, and CLI releases so historical receipts remain verifiable.
