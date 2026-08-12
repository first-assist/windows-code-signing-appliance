using System.Collections.ObjectModel;

namespace ArtifactSigning.Protocol;

public sealed class ArtifactSigningReceiptV1
{
    public const string FormatIdentifier = "ArtifactSigningReceiptV1";

    public ArtifactSigningReceiptV1(
        Guid requestId,
        string requestDigest,
        string projectId,
        string profileId,
        int profileVersion,
        string sourceRepository,
        string sourceCommit,
        string releaseVersion,
        string signerPolicyId,
        string timestampPolicyId,
        string submitterSpkiSha256,
        string approverSpkiSha256,
        string receiptSignerSpkiSha256,
        IEnumerable<ReceiptArtifactV1> unsignedArtifacts,
        IEnumerable<ReceiptArtifactV1> resultArtifacts,
        IEnumerable<ReceiptAuthenticodeArtifactV1> authenticodeArtifacts,
        string workerVersion,
        string signToolSha256,
        ulong signingAuditSequence,
        DateTimeOffset completedAt)
    {
        ArgumentNullException.ThrowIfNull(requestDigest);
        ArgumentNullException.ThrowIfNull(projectId);
        ArgumentNullException.ThrowIfNull(profileId);
        ArgumentNullException.ThrowIfNull(sourceRepository);
        ArgumentNullException.ThrowIfNull(sourceCommit);
        ArgumentNullException.ThrowIfNull(releaseVersion);
        ArgumentNullException.ThrowIfNull(signerPolicyId);
        ArgumentNullException.ThrowIfNull(timestampPolicyId);
        ArgumentNullException.ThrowIfNull(submitterSpkiSha256);
        ArgumentNullException.ThrowIfNull(approverSpkiSha256);
        ArgumentNullException.ThrowIfNull(receiptSignerSpkiSha256);
        ArgumentNullException.ThrowIfNull(unsignedArtifacts);
        ArgumentNullException.ThrowIfNull(resultArtifacts);
        ArgumentNullException.ThrowIfNull(authenticodeArtifacts);
        ArgumentNullException.ThrowIfNull(workerVersion);
        ArgumentNullException.ThrowIfNull(signToolSha256);

        if (requestId == Guid.Empty
            || !StrictJsonRules.IsLowerHex(requestDigest, 64)
            || !StrictJsonRules.IsSafeIdentifier(projectId, 64)
            || !StrictJsonRules.IsSafeIdentifier(profileId, 64)
            || profileVersion <= 0
            || !IsSourceRepository(sourceRepository)
            || !StrictJsonRules.IsCanonicalSourceCommit(sourceCommit)
            || !StrictJsonRules.IsPrintableAscii(releaseVersion, 64)
            || !StrictJsonRules.IsSafeIdentifier(signerPolicyId, 64)
            || !StrictJsonRules.IsSafeIdentifier(timestampPolicyId, 64)
            || !StrictJsonRules.IsLowerHex(submitterSpkiSha256, 64)
            || !StrictJsonRules.IsLowerHex(approverSpkiSha256, 64)
            || !StrictJsonRules.IsLowerHex(receiptSignerSpkiSha256, 64)
            || !IsCanonicalSoftwareVersion(workerVersion)
            || !StrictJsonRules.IsLowerHex(signToolSha256, 64)
            || signingAuditSequence is 0)
        {
            throw new ArgumentException(
                "Receipt identity or installed-policy evidence is invalid.");
        }

        DateTimeOffset universalCompletedAt = completedAt.ToUniversalTime();
        if (completedAt.Offset != TimeSpan.Zero
            || completedAt.Ticks % TimeSpan.TicksPerSecond is not 0)
        {
            throw new ArgumentException(
                "Receipt completion time must be UTC with whole-second precision.",
                nameof(completedAt));
        }

        ReceiptArtifactV1[] unsigned = unsignedArtifacts.ToArray();
        ReceiptArtifactV1[] results = resultArtifacts.ToArray();
        ReceiptAuthenticodeArtifactV1[] authenticode =
            authenticodeArtifacts.ToArray();
        ValidateArtifactCollections(
            unsigned,
            results,
            authenticode,
            universalCompletedAt);

        RequestId = requestId;
        RequestDigest = requestDigest;
        ProjectId = projectId;
        ProfileId = profileId;
        ProfileVersion = profileVersion;
        SourceRepository = sourceRepository;
        SourceCommit = sourceCommit;
        ReleaseVersion = releaseVersion;
        SignerPolicyId = signerPolicyId;
        TimestampPolicyId = timestampPolicyId;
        SubmitterSpkiSha256 = submitterSpkiSha256;
        ApproverSpkiSha256 = approverSpkiSha256;
        ReceiptSignerSpkiSha256 = receiptSignerSpkiSha256;
        UnsignedArtifacts = Array.AsReadOnly(unsigned);
        ResultArtifacts = Array.AsReadOnly(results);
        AuthenticodeArtifacts = Array.AsReadOnly(authenticode);
        WorkerVersion = workerVersion;
        SignToolSha256 = signToolSha256;
        SigningAuditSequence = signingAuditSequence;
        CompletedAt = universalCompletedAt;
    }

    public Guid RequestId { get; }

    public string RequestDigest { get; }

    public string ProjectId { get; }

    public string ProfileId { get; }

    public int ProfileVersion { get; }

    public string SourceRepository { get; }

    public string SourceCommit { get; }

    public string ReleaseVersion { get; }

    public string SignerPolicyId { get; }

    public string TimestampPolicyId { get; }

    public string SubmitterSpkiSha256 { get; }

    public string ApproverSpkiSha256 { get; }

    public string ReceiptSignerSpkiSha256 { get; }

    public ReadOnlyCollection<ReceiptArtifactV1> UnsignedArtifacts { get; }

    public ReadOnlyCollection<ReceiptArtifactV1> ResultArtifacts { get; }

    public ReadOnlyCollection<ReceiptAuthenticodeArtifactV1>
        AuthenticodeArtifacts
    { get; }

    public string WorkerVersion { get; }

    public string SignToolSha256 { get; }

    public ulong SigningAuditSequence { get; }

    public DateTimeOffset CompletedAt { get; }

    private static void ValidateArtifactCollections(
        ReceiptArtifactV1[] unsigned,
        ReceiptArtifactV1[] results,
        ReceiptAuthenticodeArtifactV1[] authenticode,
        DateTimeOffset completedAt)
    {
        if (unsigned.Length is 0 or > ArtifactSigningRequestJsonParser.MaximumArtifacts
            || results.Length is 0 or > ArtifactSigningRequestJsonParser.MaximumArtifacts
            || authenticode.Length is 0 or > ArtifactSigningRequestJsonParser.MaximumArtifacts
            || unsigned.Any(item => item is null)
            || results.Any(item => item is null)
            || authenticode.Any(item => item is null)
            || !HasUniqueArtifactIdentities(unsigned)
            || !HasUniqueArtifactIdentities(results)
            || !HasUniqueArtifactIdentities(authenticode))
        {
            throw new ArgumentException(
                "Receipt artifact collections are empty, oversized, duplicated, or invalid.");
        }

        Dictionary<(string Role, string File), ReceiptArtifactV1> unsignedByIdentity =
            unsigned.ToDictionary(
                item => (item.Role, item.File),
                item => item);
        Dictionary<(string Role, string File), ReceiptArtifactV1> resultByIdentity =
            results.ToDictionary(
                item => (item.Role, item.File),
                item => item);

        foreach (ReceiptArtifactV1 result in results)
        {
            if (!unsignedByIdentity.ContainsKey((result.Role, result.File)))
            {
                throw new ArgumentException(
                    "Every result artifact must map to an unsigned artifact.");
            }
        }

        foreach (ReceiptAuthenticodeArtifactV1 evidence in authenticode)
        {
            if (!unsignedByIdentity.TryGetValue(
                    (evidence.Role, evidence.File),
                    out ReceiptArtifactV1? unsignedArtifact)
                || !resultByIdentity.TryGetValue(
                    (evidence.Role, evidence.File),
                    out ReceiptArtifactV1? resultArtifact)
                || !string.Equals(
                    evidence.UnsignedSha256,
                    unsignedArtifact.Sha256,
                    StringComparison.Ordinal)
                || !string.Equals(
                    evidence.SignedSha256,
                    resultArtifact.Sha256,
                    StringComparison.Ordinal)
                || evidence.TimestampedAt > completedAt)
            {
                throw new ArgumentException(
                    "Authenticode evidence does not map to the receipt artifacts.");
            }
        }
    }

    private static bool HasUniqueArtifactIdentities<T>(
        IEnumerable<T> artifacts)
        where T : IReceiptArtifactIdentity
    {
        HashSet<string> roles = new(StringComparer.Ordinal);
        HashSet<string> files = new(StringComparer.Ordinal);
        return artifacts.All(item =>
            roles.Add(item.Role) && files.Add(item.File));
    }

    private static bool IsSourceRepository(string value)
    {
        return value.Length is > 0 and <= 128
            && value[0] is not '/'
            && value[^1] is not '/'
            && value.Split('/').All(segment =>
                StrictJsonRules.IsCanonicalFileToken(segment, 64));
    }

    private static bool IsCanonicalSoftwareVersion(string value)
    {
        string[] parts = value.Split('.');
        return parts.Length is 3
            && parts.All(part =>
                part.Length > 0
                && (part.Length is 1 || part[0] is not '0')
                && part.All(char.IsAsciiDigit)
                && uint.TryParse(part, out _));
    }
}

public sealed record ReceiptArtifactV1 : IReceiptArtifactIdentity
{
    public ReceiptArtifactV1(
        string role,
        string file,
        long size,
        string sha256)
    {
        ArgumentNullException.ThrowIfNull(role);
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(sha256);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(size);
        if (!StrictJsonRules.IsSafeIdentifier(role, 64)
            || !StrictJsonRules.IsCanonicalFileToken(file, 128)
            || !StrictJsonRules.IsLowerHex(sha256, 64))
        {
            throw new ArgumentException("Receipt artifact evidence is invalid.");
        }

        Role = role;
        File = file;
        Size = size;
        Sha256 = sha256;
    }

    public string Role { get; }

    public string File { get; }

    public long Size { get; }

    public string Sha256 { get; }
}

public sealed record ReceiptAuthenticodeArtifactV1 : IReceiptArtifactIdentity
{
    public ReceiptAuthenticodeArtifactV1(
        string role,
        string file,
        string unsignedSha256,
        string signedSha256,
        string signerThumbprint,
        string timestampAuthorityThumbprint,
        DateTimeOffset timestampedAt)
    {
        ArgumentNullException.ThrowIfNull(role);
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(unsignedSha256);
        ArgumentNullException.ThrowIfNull(signedSha256);
        ArgumentNullException.ThrowIfNull(signerThumbprint);
        ArgumentNullException.ThrowIfNull(timestampAuthorityThumbprint);
        if (!StrictJsonRules.IsSafeIdentifier(role, 64)
            || !StrictJsonRules.IsCanonicalFileToken(file, 128)
            || !StrictJsonRules.IsLowerHex(unsignedSha256, 64)
            || !StrictJsonRules.IsLowerHex(signedSha256, 64)
            || string.Equals(
                unsignedSha256,
                signedSha256,
                StringComparison.Ordinal)
            || !IsUpperThumbprint(signerThumbprint)
            || !IsUpperThumbprint(timestampAuthorityThumbprint)
            || timestampedAt.Offset != TimeSpan.Zero
            || timestampedAt.Ticks % TimeSpan.TicksPerSecond is not 0)
        {
            throw new ArgumentException(
                "Receipt Authenticode evidence is invalid.");
        }

        Role = role;
        File = file;
        UnsignedSha256 = unsignedSha256;
        SignedSha256 = signedSha256;
        SignerThumbprint = signerThumbprint;
        TimestampAuthorityThumbprint = timestampAuthorityThumbprint;
        TimestampedAt = timestampedAt;
    }

    public string Role { get; }

    public string File { get; }

    public string UnsignedSha256 { get; }

    public string SignedSha256 { get; }

    public string SignerThumbprint { get; }

    public string TimestampAuthorityThumbprint { get; }

    public DateTimeOffset TimestampedAt { get; }

    private static bool IsUpperThumbprint(string value)
    {
        return value.Length is 40
            && value.All(character =>
                character is >= '0' and <= '9' or >= 'A' and <= 'F');
    }
}

public interface IReceiptArtifactIdentity
{
    string Role { get; }

    string File { get; }
}
