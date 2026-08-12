# Signing appliance operations

Routine users operate only through `artifact-signctl` and the private API. Submitters retain the
request digest; a distinct approver verifies the review envelope and exact digest; download and
standalone verification check the receipt and closed inventory with the compiled profile. Operators
retain discovery/profile-set evidence separately because receipt V1 has no package digest. The appliance
does not build, publish, or deploy artifacts.

Start Worker before Gateway; stop Gateway before Worker. After restart, run the installed verifier,
validate mTLS readiness and the signed audit head. Monitor readiness, audit continuity, request age,
quarantine, retained bytes, certificate/revocation status, timestamp dependency, package-set drift,
service restarts, Windows Time synchronization, ACL/firewall/SignTool drift, and fixed result codes
only. Worker depends on `W32Time`; the managed provider additionally depends on Azure Arc `himds`.
Installer `0.4.1` configures and synchronizes only the fixed deployment peers before starting
signing services, and deployment V3 also verifies Arc/client-tool readiness. Immediately after a cold boot, treat
`RequestExpired` as a closed clock-readiness failure: do not approve or resubmit until Windows Time
is running, the installed verifier passes, and the client can rediscover the exact profile set.
Managed production verification also requires the Worker's FQDN-scoped Microsoft certificate-status
rules. They authorize only `www.microsoft.com` and `oneocsp.microsoft.com` on TCP 80/443 for the
Worker executable; SignTool's provider egress does not authorize the Worker to perform that separate
post-signature revocation check.

Close intake for every package or service update. Drain or terminally resolve requests, retain
external audit heads and profile-set evidence, verify the current generation, install the complete
offline release, then prove Worker/Gateway/CLI profile discovery binding before reopening intake.
Never update a profile package in place or treat a running service as readiness.
