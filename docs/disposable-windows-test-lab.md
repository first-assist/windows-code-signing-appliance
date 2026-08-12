# Disposable Windows test lab

Use a new exact-owned disposable Windows machine or VM and generated test identities only. The
machine should match the intended production Windows version, architecture, Windows SDK SignTool,
filesystem, network policy, and service behavior. The choice of physical host, hypervisor, or cloud
provider is outside the test contract.

Never use a retained signing machine, production key, copied private-key state, production
certificate provider, or post-key snapshot. Create a clean pre-key recovery point before identity
generation and destroy the exact machine, attached media, snapshots, and generated identity state
after every acceptance run.

## Acceptance boundary

The generated-key matrix and disposable appliance test together must prove:

- a sealed, statically composed package-set release installs from its exact inventory digest;
- Gateway and Worker run under distinct virtual service identities;
- only Worker can use receipt and Authenticode private keys;
- installed files, state, service definitions, ACLs, firewall, Event Log, Windows Time, SignTool,
  profile lock, and configuration match reviewed policy;
- the CLI discovers the exact package set and completes submit, independent approval, signing,
  download, and standalone verification;
- a generated non-exportable Local Machine certificate signs profile-declared PE artifacts through
  the real pinned SignTool and a loopback RFC 3161 authority;
- receipt, output, signer, timestamp, package, profile, and inventory binding are independently
  verified;
- separate service restarts, cold reboot, full update, and full rollback preserve security and
  audit continuity; and
- timestamp outage, revocation uncertainty, time drift, tampering, partial signing, and role/key
  separation failures close intake or quarantine work as designed.

## Provider-specific automation

Automation may create and control the disposable machine through a local hypervisor, cloud API, or
manual imaging process. Keep that adapter, credentials, host inventory, machine identifiers, and
run evidence in a separate private operations repository. The adapter may invoke only the closed
acceptance operations; it must not become a general remote-execution feature of the appliance.

Before any real-key deployment, retain the source commit, release inventory, package-set lock,
generated-key results, installer/restart/reboot evidence, and reviewer acceptance through the
approved evidence system. Test success proves only the reviewed release/environment combination; it
does not authorize a different target or key.
