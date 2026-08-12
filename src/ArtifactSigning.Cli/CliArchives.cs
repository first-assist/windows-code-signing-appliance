using System.Formats.Tar;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ArtifactSigning.Profiles;
using ArtifactSigning.Protocol;

namespace ArtifactSigning.Cli;

internal sealed class CliPreparedRequestArchive :
    IDisposable
{
    internal CliPreparedRequestArchive(
        string temporaryDirectory,
        string archivePath,
        ArtifactSigningRequestV1 request,
        string requestDigest)
    {
        TemporaryDirectory = temporaryDirectory;
        ArchivePath = archivePath;
        Request = request;
        RequestDigest = requestDigest;
    }

    internal string TemporaryDirectory { get; }

    internal string ArchivePath { get; }

    internal ArtifactSigningRequestV1 Request { get; }

    internal string RequestDigest { get; }

    public void Dispose()
    {
        CliFileSecurity.TryDeleteDirectory(
            TemporaryDirectory);
    }
}

internal sealed record CliReviewedRequest(
    ArtifactSigningRequestV1 Request,
    string RequestDigest,
    CmsSignerIdentity Submitter);

internal static class CliArchives
{
    private const string RequestJsonFileName =
        "request.json";
    private const string RequestSignatureFileName =
        "request.p7s";
    private const string BundleDirectoryName = "bundle";

    internal static CliPreparedRequestArchive
        PrepareRequest(
            string projectId,
            string profileId,
            string bundlePath,
            string sourceRepository,
            string sourceCommit,
        string releaseVersion,
        X509Certificate2 signingIdentity,
        TimeProvider timeProvider,
        CliProfileRegistry profiles)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(projectId);
        ArgumentException.ThrowIfNullOrWhiteSpace(profileId);
        ArgumentException.ThrowIfNullOrWhiteSpace(bundlePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(
            sourceRepository);
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceCommit);
        ArgumentException.ThrowIfNullOrWhiteSpace(
            releaseVersion);
        ArgumentNullException.ThrowIfNull(signingIdentity);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(profiles);

        ISigningProfile profile =
            profiles.ResolveUnique(profileId);
        SigningProfileDescriptor descriptor =
            profile.Descriptor;
        if (!descriptor.AllowedProjectIds.Contains(
                projectId,
                StringComparer.Ordinal)
            || !descriptor.AllowedSourceRepositories.Contains(
                sourceRepository,
                StringComparer.Ordinal)
            || descriptor.AllowedSignerPolicyIds.Count is not 1
            || descriptor.AllowedTimestampPolicyIds.Count is not 1)
        {
            throw new InvalidDataException(
                "The requested client profile authority is invalid.");
        }

        string bundle = Path.GetFullPath(bundlePath);
        ValidateBundleDirectory(bundle, descriptor);
        List<RequestArtifactV1> artifacts = [];
        long aggregateBytes = 0;
        foreach (SigningProfileArtifactDefinition definition
                 in descriptor.Artifacts)
        {
            string path = Path.Combine(
                bundle,
                definition.FileName);
            string sha256 = CliFileSecurity.Sha256File(
                path,
                definition.MaximumBytes,
                out long size);
            aggregateBytes = checked(
                aggregateBytes + size);
            if (aggregateBytes
                > descriptor.MaximumRequestBytes)
            {
                throw new InvalidDataException(
                    "The request bundle exceeds its profile bound.");
            }

            artifacts.Add(new RequestArtifactV1(
                definition.Role,
                definition.FileName,
                size,
                sha256));
        }

        DateTimeOffset requestedAt = WholeSecondNow(
            timeProvider);
        ArtifactSigningRequestV1 request = new(
            Guid.NewGuid(),
            projectId,
            descriptor.Identity.ProfileId,
            descriptor.Identity.ProfileVersion,
            sourceRepository,
            sourceCommit,
            releaseVersion,
            requestedAt,
            requestedAt.AddMinutes(15),
            CreateNonce(),
            descriptor.AllowedSignerPolicyIds[0],
            descriptor.AllowedTimestampPolicyIds[0],
            artifacts.AsReadOnly());
        SigningProfileValidationResult validation =
            profile.ValidateUnsignedBundle(
                new SigningProfileValidationContext(
                    request,
                    new BundleArtifactReader(bundle),
                    requestedAt));
        if (!validation.IsSuccess)
        {
            throw new InvalidDataException(
                "The request bundle failed its compiled client profile.");
        }

        byte[] requestJson =
            ArtifactSigningRequestJsonSerializer.Serialize(
                request);
        string requestDigest =
            RequestDigest.ComputeHex(requestJson);
        byte[] requestSignature =
            CliCertificateLoader.SignCms(
                requestJson,
                signingIdentity,
                detached: true);

        string temporaryDirectory =
            CliFileSecurity
                .CreateOwnerOnlyTemporaryDirectory();
        string archivePath = Path.Combine(
            temporaryDirectory,
            "request.tar");
        try
        {
            using FileStream archive =
                CliFileSecurity.CreateOwnerOnlyFile(
                    archivePath);
            using TarWriter writer = new(
                archive,
                TarEntryFormat.Ustar,
                leaveOpen: true);
            WriteBytesEntry(
                writer,
                RequestJsonFileName,
                requestJson);
            WriteBytesEntry(
                writer,
                RequestSignatureFileName,
                requestSignature);
            foreach (SigningProfileArtifactDefinition
                     definition in descriptor.Artifacts)
            {
                RequestArtifactV1 artifact =
                    artifacts.Single(item =>
                        string.Equals(
                            item.Role,
                            definition.Role,
                            StringComparison.Ordinal));
                WriteStableFileEntry(
                    writer,
                    string.Concat(
                        BundleDirectoryName,
                        "/",
                        definition.FileName),
                    Path.Combine(
                        bundle,
                        definition.FileName),
                    artifact);
            }

            archive.Flush(flushToDisk: true);
            return new CliPreparedRequestArchive(
                temporaryDirectory,
                archivePath,
                request,
                requestDigest);
        }
        catch
        {
            CliFileSecurity.TryDeleteDirectory(
                temporaryDirectory);
            throw;
        }
    }

    internal static CliReviewedRequest ReadAndVerifyReview(
        ReadOnlyMemory<byte> archiveBytes,
        CmsTrustPolicy submitterTrust,
        DateTimeOffset verificationTime)
    {
        ArgumentNullException.ThrowIfNull(submitterTrust);
        Dictionary<string, byte[]> entries =
            new(StringComparer.Ordinal);
        ClosedTarArchivePolicy policy = new(
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
            ],
            ArtifactSigningRequestJsonParser
                .MaximumRequestJsonBytes
            + DetachedCmsSignatureVerifier
                .MaximumSignatureBytes);
        using MemoryStream archive = new(
            archiveBytes.ToArray(),
            writable: false);
        ClosedTarReadResult read = ClosedTarArchive.Read(
            archive,
            policy,
            (header, content) =>
            {
                byte[] value =
                    new byte[checked((int)header.Length)];
                content.ReadExactly(value);
                entries.Add(header.Name, value);
            });
        if (!read.IsSuccess)
        {
            throw new InvalidDataException(
                "The signing review archive is invalid.");
        }

        byte[] requestJson =
            entries[RequestJsonFileName];
        RequestJsonParseResult parsed =
            ArtifactSigningRequestJsonParser.Parse(
                requestJson);
        TrustedDetachedCmsVerificationResult verified =
            TrustedDetachedCmsSignatureVerifier.Verify(
                requestJson,
                entries[RequestSignatureFileName],
                submitterTrust,
                verificationTime);
        if (!parsed.IsSuccess
            || parsed.Request is null
            || !verified.IsSuccess
            || verified.Signer is null)
        {
            throw new InvalidDataException(
                "The signing review is not trusted.");
        }

        return new CliReviewedRequest(
            parsed.Request,
            RequestDigest.ComputeHex(requestJson),
            verified.Signer);
    }

    private static void ValidateBundleDirectory(
        string path,
        SigningProfileDescriptor descriptor)
    {
        DirectoryInfo directory = new(path);
        directory.Refresh();
        if (!directory.Exists
            || directory.Attributes.HasFlag(
                FileAttributes.ReparsePoint)
            || directory.LinkTarget is not null)
        {
            throw new InvalidDataException(
                "The request bundle directory is invalid.");
        }

        HashSet<string> expected = descriptor.Artifacts
            .Select(item => item.FileName)
            .ToHashSet(StringComparer.Ordinal);
        string?[] actual = Directory
            .EnumerateFileSystemEntries(path)
            .Select(Path.GetFileName)
            .ToArray();
        if (actual.Length != expected.Count
            || actual.Any(item =>
                item is null
                || !expected.Contains(item)))
        {
            throw new InvalidDataException(
                "The request bundle inventory is invalid.");
        }
    }

    private static void WriteBytesEntry(
        TarWriter writer,
        string name,
        byte[] content)
    {
        UstarTarEntry entry = CreateEntry(
            name,
            new MemoryStream(
                content,
                writable: false));
        writer.WriteEntry(entry);
    }

    private static void WriteStableFileEntry(
        TarWriter writer,
        string name,
        string path,
        RequestArtifactV1 expected)
    {
        using FileStream input = new(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.SequentialScan);
        if (input.Length != expected.Size)
        {
            throw new InvalidDataException(
                "A request artifact changed during packaging.");
        }

        using HashingReadStream hashing = new(
            input,
            expected.Size);
        UstarTarEntry entry = CreateEntry(name, hashing);
        writer.WriteEntry(entry);
        if (hashing.BytesRead != expected.Size
            || !string.Equals(
                hashing.GetSha256(),
                expected.Sha256,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "A request artifact changed during packaging.");
        }
    }

    private static UstarTarEntry CreateEntry(
        string name,
        Stream content)
    {
        return new UstarTarEntry(
            TarEntryType.RegularFile,
            name)
        {
            DataStream = content,
            Gid = 0,
            Uid = 0,
            GroupName = string.Empty,
            UserName = string.Empty,
            Mode =
                UnixFileMode.UserRead
                | UnixFileMode.UserWrite,
            ModificationTime = DateTimeOffset.UnixEpoch,
        };
    }

    private static string CreateNonce()
    {
        return Convert.ToBase64String(
                RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static DateTimeOffset WholeSecondNow(
        TimeProvider timeProvider)
    {
        DateTimeOffset now =
            timeProvider.GetUtcNow().ToUniversalTime();
        return new DateTimeOffset(
            now.Year,
            now.Month,
            now.Day,
            now.Hour,
            now.Minute,
            now.Second,
            TimeSpan.Zero);
    }

    private sealed class HashingReadStream : Stream
    {
        private readonly Stream _inner;
        private readonly long _length;
        private readonly IncrementalHash _hash =
            IncrementalHash.CreateHash(
                HashAlgorithmName.SHA256);
        private bool _finalized;

        internal HashingReadStream(
            Stream inner,
            long length)
        {
            _inner = inner;
            _length = length;
        }

        internal long BytesRead { get; private set; }

        internal string GetSha256()
        {
            if (_finalized)
            {
                throw new InvalidOperationException(
                    "Artifact hash was already finalized.");
            }

            _finalized = true;
            return Convert.ToHexStringLower(
                _hash.GetHashAndReset());
        }

        public override int Read(
            byte[] buffer,
            int offset,
            int count)
        {
            int read = _inner.Read(
                buffer,
                offset,
                count);
            if (read > 0)
            {
                _hash.AppendData(
                    buffer,
                    offset,
                    read);
                BytesRead = checked(BytesRead + read);
            }

            return read;
        }

        public override int Read(Span<byte> buffer)
        {
            int read = _inner.Read(buffer);
            if (read > 0)
            {
                _hash.AppendData(buffer[..read]);
                BytesRead = checked(BytesRead + read);
            }

            return read;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _hash.Dispose();
                _inner.Dispose();
            }

            base.Dispose(disposing);
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => _length;

        public override long Position
        {
            get => BytesRead;
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override long Seek(
            long offset,
            SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(
            byte[] buffer,
            int offset,
            int count)
        {
            throw new NotSupportedException();
        }
    }

    private sealed class BundleArtifactReader(
        string directory) : IProfileArtifactReader
    {
        public Stream OpenRead(string fileName)
        {
            return new FileStream(
                Path.Combine(directory, fileName),
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                64 * 1024,
                FileOptions.SequentialScan);
        }
    }
}
