# Project-agnostic signing API contract

## Transport and authorization

Kestrel listens only on a reviewed private address and requires a client certificate during the TLS
handshake. TLS 1.2+ uses operating-system defaults. There is no plaintext listener, redirect,
HTTP/3, WebSocket, CORS, cookie, bearer-token, reverse-proxy identity header, or network profile
administration endpoint. Every response is `Cache-Control: no-store`.

The Gateway validates the transport identity by exact certificate and SPKI SHA-256 allowlist, then
validates one detached CMS signer over exact request bytes. CMS validation requires bounded input,
one signer, SHA-256, exact configured SPKI, leaf validity, digital-signature use, required EKU,
configured public trust, and the deployment revocation policy. Production uses online revocation
and fails closed when status is unknown.

Roles are Submitter, Approver, Auditor, and offline Administrator. Production requires distinct
submitter and approver SPKIs. Authorization is an exact installed
`(ProjectId, ProfileId, ProfileVersion, Role)` tuple; display names confer no authority.

## Installed profiles and package binding

`GET /v1/profiles` exposes only tuples visible to the authenticated caller. It is discovery
evidence, not a package-management surface. A current response entry is:

```json
{
  "Format": "ArtifactSigningProfilesResponseV2",
  "Profiles": [{
    "ProjectId": "example-project",
    "ProfileId": "ExampleBundleV1",
    "ProfileVersion": 1,
    "RequestFormat": "ArtifactSigningRequestV1",
    "MaximumRequestBytes": 104857600,
    "ProfileSetSha256": "0000000000000000000000000000000000000000000000000000000000000000",
    "PackageId": "Example.Profile.Package",
    "PackageVersion": "1.0.0",
    "PackageSha256": "0000000000000000000000000000000000000000000000000000000000000000",
    "AssemblySha256": "0000000000000000000000000000000000000000000000000000000000000000",
    "DescriptorSha256": "0000000000000000000000000000000000000000000000000000000000000000"
  }]
}
```

The CLI accepts this response only when its statically linked package set has the same profile-set,
package ID, canonical SemVer, package, assembly, and descriptor SHA-256 values. The response does not reveal source paths,
assembly names, type names, certificate material, SignTool options, policy internals, or another
project's profiles.

Profile packages are separately built, offline operator inputs. The appliance's offline composer
verifies canonical `profile-package.txt` files and assembly digests, emits the package-set lock and
static registration source, and compiles the result into Gateway, Worker, and CLI. Gateway and
Worker configuration format V2 each carry the exact `ProfileSetSha256` and fail startup if it does
not equal the compiled set. No API, archive, configuration, or runtime path loads profile code.

## Requests and approval

`POST /v1/requests` accepts only
`application/vnd.artifact-signing.request.v1+tar`. The archive is uncompressed USTAR and contains
exactly `request.json`, `request.p7s`, and the profile's exact declared files. It rejects links,
directories, devices, PAX/GNU extensions, duplicates, traversal, alternate-data-stream syntax,
unexpected entries, compression, and trailing nonzero data. The CMS is detached over exact
`request.json` bytes.

`ArtifactSigningRequestV1` is exact PascalCase JSON: non-nil lowercase UUID, safe project/profile
identifiers, positive profile version and artifact sizes, canonical source commit, whole-second UTC
timestamps no more than fifteen minutes apart, a 32-byte base64url nonce, installed signer and
timestamp policy aliases, and one through sixty-four uniquely named artifacts. Every artifact uses
canonical lowercase SHA-256. Unknown, duplicate, missing, escaped, malformed UTF-8, comment, and
trailing-comma properties are rejected.

The selected compiled profile closes the projects, repositories, artifact roles/filenames/kinds,
per-entry and aggregate limits, policy aliases, unsigned semantics, finalization, and finalized
validation. It receives only an already admitted artifact reader; it must not receive a directory
or client-selected path. Gateway and Worker independently stream and hash every artifact.

`POST /v1/requests/{requestId}/approvals` accepts an attached approval CMS bound to the exact
request digest. It never accepts a user-supplied executable, output path, certificate selector,
store, timestamp URL, SignTool option, provider, package, or profile implementation.

## Signing, output, and failure

The Worker resolves installed aliases to one protected signing policy, verifies at startup that its
configuration names its exact compiled package set, then rechecks the request, approval, profile,
and every byte before key use. It invokes only the
hash/version-pinned absolute SignTool executable directly with `UseShellExecute=false` and a fixed
argument grammar. It fails closed on catalog state, existing embedded signature, signer mismatch,
timestamp or revocation uncertainty, partial signing, output publication failure, audit failure,
or restart ambiguity.

Only the Worker finalizes a bundle after authoritative Windows signature verification. It emits a
deterministic profile result, receipt JSON, and detached receipt CMS; the result TAR contains only
that closed inventory. Receipt V1 preserves the request/profile-version/policy/artifact relationship;
the package and package-set digests remain separately retained release/discovery evidence rather
than receipt fields. Raw SignTool output, exception text, paths,
certificate contents, and operating-system diagnostics never cross the API.
