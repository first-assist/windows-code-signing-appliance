# Timestamp relay operations

`ArtifactSigning.TimestampRelay` is a narrow Linux service between the isolated Windows Worker
and one reviewed public RFC 3161 endpoint. It is not a general proxy, timestamp authority,
artifact store or virtualization-host service.

This relay is the Local Machine certificate track's fixed timestamp dependency. Microsoft Artifact
Signing uses its Dlib-selected RFC 3161 endpoint directly through deployment V3's exact
process-scoped SignTool egress; it does not use this relay. The managed Worker probes the local Arc
HIMDS boundary. Follow `microsoft-artifact-signing.md` for its identity, timestamp, egress, and
native acceptance requirements.

## Network placement

Install the relay in a separate contained Linux workload. Never install it on a virtualization
management host or the Windows signing machine. Its private listener firewall admits only the dedicated
Worker VM address. Its egress firewall admits only every exact address in `UpstreamAddresses` on
the configured `UpstreamUrl` port. Deny all other relay ingress and egress.

The relay accepts:

- `POST /timestamp` with exactly `application/timestamp-query`; and
- `GET /health/live` or `GET /health/ready` from the same allowlisted Worker address.

It returns a successful upstream token only as exactly `application/timestamp-reply`. It does not
follow redirects, use a proxy, resolve the upstream host for connection selection, forward client
headers, persist request/response bytes or expose upstream diagnostics. Upstream TLS still
validates the configured hostname through system trust with online certificate revocation; the
configured IP list prevents DNS-selected destination changes.

## Build and install

Publish the reviewed relay version for the target Linux architecture:

```bash
dotnet publish src/ArtifactSigning.TimestampRelay/ArtifactSigning.TimestampRelay.csproj \
  --configuration Release \
  --runtime linux-x64 \
  --self-contained true \
  -p:PublishSingleFile=true
```

Install those exact release bytes beneath `/opt/artifact-signing/timestamp-relay`, owned by root
and not writable by `artifact-timestamp`. Create a non-interactive `artifact-timestamp` service
account. Install the reviewed
`deploy/linux/timestamp-relay/artifact-signing-timestamp-relay.service` unit.

Relay `0.2.2` explicitly sets systemd `MemoryDenyWriteExecute=no`. The self-contained .NET 10
runtime requires executable JIT mappings and terminates before binding when systemd applies the
blanket denial. This does not disable the runtime's write-xor-execute behavior. Treat any future
change to executable-memory policy, runtime publication mode or this unit as a versioned relay
change that must pass the native Linux service-start and readiness matrix.

Install configuration at `/etc/artifact-signing/timestamp-relay.json`, owned by the dedicated
service account with mode `0600` and exactly one hard link. The checked-in example contains
documentation-only addresses and the reserved `.invalid` hostname; it cannot contact a timestamp
service. Replace every address with a separately reviewed network assignment. Production mode
requires a canonical HTTPS upstream URL and a non-loopback private bind address.

`UpstreamAddresses` is the complete connection allowlist, not a DNS cache. Review and deploy an
address rotation as a versioned configuration/firewall change. Do not broaden it to a subnet.
The adjacent `timestamp-relay.nft.example` is a complete deny-by-default illustration using only
documentation addresses. Merge reviewed equivalents into the workload's actual firewall rather
than applying the example blindly. If upstream TLS revocation requires certificate-status
network access, identify, pin and explicitly accept those dependencies during deployment; do not
silently relax egress or revocation.

After configuration and host firewall rules are installed:

```bash
systemctl daemon-reload
systemctl enable --now artifact-signing-timestamp-relay.service
systemctl is-active artifact-signing-timestamp-relay.service
```

From the allowlisted Worker network only, `/health/ready` returns the exact body
`{"Status":"Ready"}` when a pinned upstream TCP connection and, for HTTPS, hostname-authenticated
TLS handshake currently succeed. This is an availability precheck; SignTool and Windows still
cryptographically validate every returned RFC 3161 token.

Configure each Worker timestamp policy to use
`http://<private-relay-address>:<port>/timestamp`. The Worker derives the fixed
`/health/ready` URI from that origin, refuses proxies and redirects, and publishes the result only
as a signed coarse readiness boolean.
The health request is made by `ArtifactSigning.Worker.exe`, while the RFC 3161 timestamp request is
made by the separately hash-pinned `signtool.exe` child. The Windows appliance therefore requires
two distinct outbound allow rules to the same exact relay address and port: one scoped to the
Worker service for readiness and one scoped to SignTool for timestamping. Do not merge them into an
all-program rule.

## Failure and review

The relay permits one in-flight timestamp request and requires an installed limit between one and
30 requests per minute; the checked-in example uses two. Excess work is rejected without queueing.
Requests are limited to 64 KiB, responses to 1 MiB, response headers to 16 KiB and total upstream
time to 15 seconds or less. Health requests have an independent concurrency-one, six-per-minute,
zero-queue bound so health probing cannot consume the timestamp budget or create an upstream
handshake flood.

Ordinary relay logs contain only the request SHA-256, byte count, elapsed milliseconds and fixed
result code. They never contain token bytes, certificate contents, local paths or raw upstream
errors. Treat repeated `UpstreamUnavailable`, `UpstreamRejected`, `ResponseInvalid` or rate-limit
events as an availability/security incident. The Worker fails closed and no signed bundle is
published when timestamping or token validation is uncertain.
