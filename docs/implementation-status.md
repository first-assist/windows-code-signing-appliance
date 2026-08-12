# Implementation status

The generic appliance supports separately built compiled profile packages through offline static
composition. This repository contains the protocol, profile contract and package-set validation,
Gateway, listenerless Worker, cross-platform CLI, Windows signing adapter, timestamp relay,
installer, audit/state handling, and generated-key test infrastructure. Consumer-specific profile
code, client guides, compatibility corpora, and lab adapters are external.

Current composition uses `ArtifactSigningProfilePackageV1`, package-set lock V1, static generated
registrations, Gateway configuration V2, and Worker configuration V3 with `ProfileSetSha256`.
Legacy Worker V2 remains accepted only for the Local Machine provider. Profile discovery and CLI
submission bind the same package set. There is no runtime profile loading.

Receipt V1 retains profile identity and version but does not embed package or package-set digests.
Those values are retained separately in the profile discovery response, package-set lock, and sealed
release inventory; historical verification requires the corresponding retained CLI/profile release.

Remaining release gates are environment-specific: run the full warnings-denied build and tests,
dependency audit, secret scan, native Windows generated-key matrix, installer/restart/reboot,
profile discovery binding, update/rollback, and provider-specific acceptance. Source completion
does not authorize a key, certificate, VM, snapshot, or production deployment.

The Microsoft Artifact Signing provider has separately passed an isolated Windows service,
Azure Arc managed-identity, role-removal, endpoint-block, client-tool-tamper, recovery, and cold-boot
proof using a Public Trust Test profile. Deployment V3 now packages and verifies the complete
client-tools inventory, requires only managed identity, reconciles the Worker service identity into
Azure Arc's local access group, verifies Arc service provenance, and applies a closed
process/service-scoped egress policy. The complete native installer/update/rollback and end-to-end
appliance matrix remains a per-release gate.
