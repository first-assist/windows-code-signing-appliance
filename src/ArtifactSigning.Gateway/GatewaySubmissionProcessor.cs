using System.Security.Cryptography;
using ArtifactSigning.Profiles;
using ArtifactSigning.Protocol;
using ArtifactSigning.Windows;

namespace ArtifactSigning.Gateway;

public enum GatewaySubmissionError
{
    None,
    TransportIdentityMismatch,
    ArchiveInvalid,
    RequestInvalid,
    RequestExpired,
    SignatureInvalid,
    ProfileInvalid,
    Conflict,
    QueueFull,
    StorageFailed,
}

public sealed record GatewaySubmissionResult(
    GatewaySubmissionError Error,
    GatewayRequestRecord? Request)
{
    public bool IsSuccess =>
        Error is GatewaySubmissionError.None
        && Request is not null;
}

public sealed class GatewaySubmitterPolicy
{
    public GatewaySubmitterPolicy(
        string projectId,
        string profileId,
        int profileVersion,
        CmsTrustPolicy trustPolicy)
    {
        ArgumentNullException.ThrowIfNull(projectId);
        ArgumentNullException.ThrowIfNull(profileId);
        ArgumentNullException.ThrowIfNull(trustPolicy);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(
            profileVersion);
        if (!GatewayContractRules.IsSafeIdentifier(projectId)
            || !GatewayContractRules.IsSafeIdentifier(profileId))
        {
            throw new ArgumentException(
                "Submitter policy identity is invalid.");
        }

        ProjectId = projectId;
        ProfileId = profileId;
        ProfileVersion = profileVersion;
        TrustPolicy = trustPolicy;
    }

    public string ProjectId { get; }

    public string ProfileId { get; }

    public int ProfileVersion { get; }

    public CmsTrustPolicy TrustPolicy { get; }
}

public sealed class GatewaySubmissionProcessor
{
    public const string RequestJsonFileName = "request.json";
    public const string RequestSignatureFileName = "request.p7s";
    public const string BundleDirectoryName = "bundle";

    private readonly GatewayStateStore _stateStore;
    private readonly SigningProfileRegistry _profiles;
    private readonly TimeProvider _timeProvider;

    public GatewaySubmissionProcessor(
        GatewayStateStore stateStore,
        SigningProfileRegistry profiles,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(stateStore);
        ArgumentNullException.ThrowIfNull(profiles);
        _stateStore = stateStore;
        _profiles = profiles;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public GatewaySubmissionResult Process(
        Stream archive,
        GatewaySubmitterPolicy submitterPolicy,
        string authenticatedSpkiSha256)
    {
        ArgumentNullException.ThrowIfNull(archive);
        ArgumentNullException.ThrowIfNull(submitterPolicy);
        GatewayContractRules.ValidateSpki(
            authenticatedSpkiSha256,
            nameof(authenticatedSpkiSha256));
        if (!string.Equals(
                authenticatedSpkiSha256,
                submitterPolicy.TrustPolicy
                    .ExpectedSignerSpkiSha256,
                StringComparison.Ordinal))
        {
            return Failure(
                GatewaySubmissionError
                    .TransportIdentityMismatch);
        }

        ISigningProfile? profile = _profiles.Resolve(
            submitterPolicy.ProfileId,
            submitterPolicy.ProfileVersion);
        if (profile is null
            || !profile.Descriptor.AllowedProjectIds.Contains(
                submitterPolicy.ProjectId,
                StringComparer.Ordinal))
        {
            return Failure(GatewaySubmissionError.ProfileInvalid);
        }

        string receiving =
            _stateStore.Layout.CreateReceivingDirectoryPath();
        try
        {
            Directory.CreateDirectory(receiving);
            string bundle = Path.Combine(
                receiving,
                BundleDirectoryName);
            Directory.CreateDirectory(bundle);
            ClosedTarArchivePolicy archivePolicy =
                CreateArchivePolicy(profile.Descriptor);
            Dictionary<string, string> destinations =
                CreateDestinations(
                    receiving,
                    bundle,
                    profile.Descriptor);
            ClosedTarReadResult archiveResult =
                ClosedTarArchive.Read(
                    archive,
                    archivePolicy,
                    (header, content) => CopyEntry(
                        header,
                        content,
                        destinations));
            if (!archiveResult.IsSuccess)
            {
                TryDeleteOwnedDirectory(receiving);
                return Failure(
                    GatewaySubmissionError.ArchiveInvalid);
            }

            byte[] requestJson = ReadBounded(
                destinations[RequestJsonFileName],
                ArtifactSigningRequestJsonParser
                    .MaximumRequestJsonBytes);
            byte[] requestSignature = ReadBounded(
                destinations[RequestSignatureFileName],
                DetachedCmsSignatureVerifier
                    .MaximumSignatureBytes);
            RequestJsonParseResult requestResult =
                ArtifactSigningRequestJsonParser.Parse(requestJson);
            if (!requestResult.IsSuccess
                || requestResult.Request is null)
            {
                TryDeleteOwnedDirectory(receiving);
                return Failure(
                    GatewaySubmissionError.RequestInvalid);
            }

            ArtifactSigningRequestV1 request =
                requestResult.Request;
            DateTimeOffset now = GetWholeSecondUtcNow();
            if (request.RequestedAt > now
                || now >= request.ExpiresAt)
            {
                TryDeleteOwnedDirectory(receiving);
                return Failure(
                    GatewaySubmissionError.RequestExpired);
            }

            if (!MatchesPolicy(
                    request,
                    submitterPolicy,
                    profile.Descriptor)
                || !ArchiveMatchesRequest(
                    request,
                    archiveResult,
                    profile.Descriptor))
            {
                TryDeleteOwnedDirectory(receiving);
                return Failure(
                    GatewaySubmissionError.ProfileInvalid);
            }

            TrustedDetachedCmsVerificationResult signature =
                TrustedDetachedCmsSignatureVerifier.Verify(
                    requestJson,
                    requestSignature,
                    submitterPolicy.TrustPolicy,
                    now);
            if (!signature.IsSuccess
                || signature.Signer is null
                || !string.Equals(
                    signature.Signer
                        .SubjectPublicKeyInfoSha256,
                    authenticatedSpkiSha256,
                    StringComparison.Ordinal))
            {
                TryDeleteOwnedDirectory(receiving);
                return Failure(
                    GatewaySubmissionError.SignatureInvalid);
            }

            GatewayProfileArtifactReader artifactReader = new(
                bundle,
                profile.Descriptor);
            SigningProfileValidationResult validation =
                profile.ValidateUnsignedBundle(
                    new SigningProfileValidationContext(
                        request,
                        artifactReader,
                        now));
            if (!validation.IsSuccess)
            {
                TryDeleteOwnedDirectory(receiving);
                return Failure(
                    GatewaySubmissionError.ProfileInvalid);
            }

            string requestDigest =
                RequestDigest.ComputeHex(requestJson);
            string pending =
                _stateStore.Layout.GetPendingRequestDirectory(
                    request.RequestId);
            string ready =
                _stateStore.Layout.GetReadyRequestDirectory(
                    request.RequestId);
            GatewayRequestRecord? existing =
                _stateStore.GetRequest(request.RequestId);
            if (existing is not null)
            {
                TryDeleteOwnedDirectory(receiving);
                return string.Equals(
                        existing.RequestDigest,
                        requestDigest,
                        StringComparison.Ordinal)
                    && string.Equals(
                        existing.SubmitterSpkiSha256,
                        authenticatedSpkiSha256,
                        StringComparison.Ordinal)
                    && (Directory.Exists(pending)
                        || Directory.Exists(ready))
                    ? Success(existing)
                    : Failure(
                        GatewaySubmissionError.Conflict);
            }

            if (Directory.Exists(pending))
            {
                TryDeleteOwnedDirectory(receiving);
                return Failure(GatewaySubmissionError.Conflict);
            }

            Directory.Move(receiving, pending);
            GatewayMutationResult admitted =
                _stateStore.AdmitPending(
                    request,
                    requestDigest,
                    authenticatedSpkiSha256,
                    now);
            if ((admitted.Outcome is GatewayMutationOutcome.Applied
                    or GatewayMutationOutcome.AlreadyApplied)
                && admitted.Request is not null)
            {
                return Success(admitted.Request!);
            }

            TryDeleteOwnedDirectory(pending);
            return Failure(
                admitted.Outcome
                    is GatewayMutationOutcome.CapacityExceeded
                    ? GatewaySubmissionError.QueueFull
                    : GatewaySubmissionError.Conflict);
        }
        catch (Exception exception)
            when (exception is not OutOfMemoryException)
        {
            TryDeleteOwnedDirectory(receiving);
            return Failure(GatewaySubmissionError.StorageFailed);
        }
    }

    private static ClosedTarArchivePolicy CreateArchivePolicy(
        SigningProfileDescriptor descriptor)
    {
        List<ClosedTarEntryPolicy> entries =
        [
            new ClosedTarEntryPolicy(
                RequestJsonFileName,
                1,
                ArtifactSigningRequestJsonParser
                    .MaximumRequestJsonBytes),
            new ClosedTarEntryPolicy(
                RequestSignatureFileName,
                1,
                DetachedCmsSignatureVerifier
                    .MaximumSignatureBytes),
        ];
        entries.AddRange(descriptor.Artifacts.Select(definition =>
            new ClosedTarEntryPolicy(
                $"{BundleDirectoryName}/{definition.FileName}",
                1,
                definition.MaximumBytes)));
        return new ClosedTarArchivePolicy(
            entries,
            ClosedTarArchivePolicy.MaximumArchiveEntryBytes);
    }

    private static Dictionary<string, string> CreateDestinations(
            string receiving,
            string bundle,
            SigningProfileDescriptor descriptor)
    {
        Dictionary<string, string> destinations =
            new(StringComparer.Ordinal)
            {
                [RequestJsonFileName] = Path.Combine(
                    receiving,
                    RequestJsonFileName),
                [RequestSignatureFileName] = Path.Combine(
                    receiving,
                    RequestSignatureFileName),
            };
        foreach (SigningProfileArtifactDefinition definition
                 in descriptor.Artifacts)
        {
            destinations.Add(
                $"{BundleDirectoryName}/{definition.FileName}",
                Path.Combine(bundle, definition.FileName));
        }

        return destinations;
    }

    private static void CopyEntry(
        ClosedTarEntryHeader header,
        Stream content,
        Dictionary<string, string> destinations)
    {
        if (!destinations.TryGetValue(
                header.Name,
                out string? path))
        {
            throw new InvalidDataException(
                "Archive destination is not installed.");
        }

        using FileStream output = new(
            path,
            new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                BufferSize = 64 * 1024,
                Options = FileOptions.SequentialScan
                    | FileOptions.WriteThrough,
            });
        content.CopyTo(output);
        output.Flush(flushToDisk: true);
    }

    private static byte[] ReadBounded(
        string path,
        int maximumBytes)
    {
        using FileStream stream =
            GatewayDirectFile.OpenRead(path);
        if (stream.Length is <= 0
            || stream.Length > maximumBytes)
        {
            throw new InvalidDataException(
                "Gateway input exceeds its installed bound.");
        }

        byte[] bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        return bytes;
    }

    private static bool MatchesPolicy(
        ArtifactSigningRequestV1 request,
        GatewaySubmitterPolicy policy,
        SigningProfileDescriptor descriptor)
    {
        return string.Equals(
                request.ProjectId,
                policy.ProjectId,
                StringComparison.Ordinal)
            && string.Equals(
                request.ProfileId,
                policy.ProfileId,
                StringComparison.Ordinal)
            && request.ProfileVersion == policy.ProfileVersion
            && descriptor.AllowedSourceRepositories.Contains(
                request.SourceRepository,
                StringComparer.Ordinal)
            && descriptor.AllowedSignerPolicyIds.Contains(
                request.SignerPolicyId,
                StringComparer.Ordinal)
            && descriptor.AllowedTimestampPolicyIds.Contains(
                request.TimestampPolicyId,
                StringComparer.Ordinal);
    }

    private static bool ArchiveMatchesRequest(
        ArtifactSigningRequestV1 request,
        ClosedTarReadResult archive,
        SigningProfileDescriptor descriptor)
    {
        Dictionary<string, ClosedTarEntryResult> entries =
            archive.Entries.ToDictionary(
                entry => entry.Name,
                StringComparer.Ordinal);
        foreach (SigningProfileArtifactDefinition definition
                 in descriptor.Artifacts)
        {
            RequestArtifactV1? requested =
                request.Artifacts.SingleOrDefault(artifact =>
                    string.Equals(
                        artifact.Role,
                        definition.Role,
                        StringComparison.Ordinal)
                    && string.Equals(
                        artifact.File,
                        definition.FileName,
                        StringComparison.Ordinal));
            if (requested is null
                || !entries.TryGetValue(
                    $"{BundleDirectoryName}/{definition.FileName}",
                    out ClosedTarEntryResult? observed)
                || observed.Size != requested.Size
                || !FixedTimeDigestEquals(
                    observed.Sha256,
                    requested.Sha256))
            {
                return false;
            }
        }

        return request.Artifacts.Count
            == descriptor.Artifacts.Count;
    }

    private static bool FixedTimeDigestEquals(
        string first,
        string second)
    {
        return first.Length is 64
            && second.Length is 64
            && CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(first),
                Convert.FromHexString(second));
    }

    private DateTimeOffset GetWholeSecondUtcNow()
    {
        DateTimeOffset now =
            _timeProvider.GetUtcNow().ToUniversalTime();
        return new DateTimeOffset(
            now.Year,
            now.Month,
            now.Day,
            now.Hour,
            now.Minute,
            now.Second,
            TimeSpan.Zero);
    }

    private static void TryDeleteOwnedDirectory(string path)
    {
        try
        {
            if (!Directory.Exists(path))
            {
                return;
            }

            FileAttributes attributes = File.GetAttributes(path);
            if (attributes.HasFlag(FileAttributes.Directory)
                && !attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (IOException)
        {
            // Bounded rejected input cleanup is best effort.
        }
        catch (UnauthorizedAccessException)
        {
            // Bounded rejected input cleanup is best effort.
        }
    }

    private static GatewaySubmissionResult Success(
        GatewayRequestRecord request)
    {
        return new GatewaySubmissionResult(
            GatewaySubmissionError.None,
            request);
    }

    private static GatewaySubmissionResult Failure(
        GatewaySubmissionError error)
    {
        return new GatewaySubmissionResult(error, null);
    }
}

internal sealed class GatewayProfileArtifactReader :
    IProfileArtifactReader
{
    private readonly Dictionary<string, string> _paths;

    internal GatewayProfileArtifactReader(
        string trustedBundleRoot,
        SigningProfileDescriptor descriptor)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            trustedBundleRoot);
        ArgumentNullException.ThrowIfNull(descriptor);
        if (!Path.IsPathFullyQualified(trustedBundleRoot))
        {
            throw new ArgumentException(
                "Gateway artifact root must be fully qualified.",
                nameof(trustedBundleRoot));
        }

        string root = Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(trustedBundleRoot));
        _paths = descriptor.Artifacts.ToDictionary(
            definition => definition.FileName,
            definition => Path.Combine(
                root,
                definition.FileName),
            StringComparer.Ordinal);
    }

    public Stream OpenRead(string fileName)
    {
        ArgumentNullException.ThrowIfNull(fileName);
        if (!_paths.TryGetValue(fileName, out string? path))
        {
            throw new FileNotFoundException(
                "Profile requested an artifact outside its compiled inventory.");
        }

        return GatewayDirectFile.OpenRead(path);
    }
}

internal static class GatewayDirectFile
{
    internal static FileStream OpenRead(string trustedAbsolutePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            trustedAbsolutePath);
        if (!Path.IsPathFullyQualified(trustedAbsolutePath))
        {
            throw new ArgumentException(
                "Gateway file path must be fully qualified.",
                nameof(trustedAbsolutePath));
        }

        FileAttributes attributes =
            File.GetAttributes(trustedAbsolutePath);
        if (attributes.HasFlag(FileAttributes.Directory)
            || attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidDataException(
                "Gateway input is not a direct regular file.");
        }

        return WindowsDirectFileReader
            .OpenReadDirectSingleLinkFile(
                trustedAbsolutePath);
    }
}
