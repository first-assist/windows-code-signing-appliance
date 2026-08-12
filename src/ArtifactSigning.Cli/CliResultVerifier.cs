using System.Collections.ObjectModel;
using System.Formats.Tar;
using System.Security.Cryptography;
using ArtifactSigning.Profiles;
using ArtifactSigning.Protocol;

namespace ArtifactSigning.Cli;

internal sealed record CliVerifiedResult(
    Guid RequestId,
    string RequestDigest,
    string ProjectId,
    string ProfileId,
    int ProfileVersion,
    string SourceCommit,
    string ReleaseVersion,
    string ReceiptDigest,
    DateTimeOffset CompletedAt);

internal static class CliResultVerifier
{
    private const string ReceiptJsonName =
        "signing-receipt.json";
    private const string ReceiptSignatureName =
        "signing-receipt.p7s";
    private const string BundlePrefix = "bundle/";

    internal static CliVerifiedResult Verify(
        string archivePath,
        CmsTrustPolicy receiptTrust,
        DateTimeOffset verificationTime,
        CliProfileRegistry profiles,
        Guid? expectedRequestId = null,
        string? expectedRequestDigest = null)
    {
        ArgumentNullException.ThrowIfNull(receiptTrust);
        ArgumentNullException.ThrowIfNull(profiles);
        string fullPath =
            CliFileSecurity.RequireAbsolutePath(
                archivePath);
        CliFileSecurity.ValidateDirectRegularFile(
            fullPath,
            SigningServiceClient
                .MaximumArchiveResponseBytes);
        IReadOnlyList<ObservedEntry> observed =
            InspectInventory(fullPath);
        long total = observed.Sum(item => item.Length);
        if (total is <= 0
            || total
                > ClosedTarArchivePolicy
                    .MaximumArchiveEntryBytes)
        {
            throw InvalidResult();
        }

        ClosedTarArchivePolicy policy = new(
            observed.Select(item =>
                new ClosedTarEntryPolicy(
                    item.Name,
                    1,
                    item.Length)),
            total);
        string temporaryDirectory =
            CliFileSecurity
                .CreateOwnerOnlyTemporaryDirectory();
        string bundleDirectory = Path.Combine(
            temporaryDirectory,
            "bundle");
        try
        {
            CreateOwnerOnlyDirectory(bundleDirectory);
            using FileStream archive =
                File.OpenRead(fullPath);
            ClosedTarReadResult read = ClosedTarArchive.Read(
                archive,
                policy,
                (header, content) =>
                {
                    string destination =
                        GetExtractionPath(
                            temporaryDirectory,
                            header.Name);
                    using FileStream output =
                        CliFileSecurity
                            .CreateOwnerOnlyFile(
                                destination);
                    content.CopyTo(output);
                    output.Flush(flushToDisk: true);
                });
            if (!read.IsSuccess)
            {
                throw InvalidResult();
            }

            byte[] receiptJson =
                CliFileSecurity.ReadBounded(
                    Path.Combine(
                        temporaryDirectory,
                        ReceiptJsonName),
                    ArtifactSigningReceiptJsonSerializer
                        .MaximumReceiptJsonBytes);
            byte[] receiptSignature =
                CliFileSecurity.ReadBounded(
                    Path.Combine(
                        temporaryDirectory,
                        ReceiptSignatureName),
                    DetachedCmsSignatureVerifier
                        .MaximumSignatureBytes);
            ReceiptJsonParseResult parsed =
                ArtifactSigningReceiptJsonParser.Parse(
                    receiptJson);
            TrustedDetachedCmsVerificationResult verified =
                TrustedDetachedCmsSignatureVerifier.Verify(
                    receiptJson,
                    receiptSignature,
                    receiptTrust,
                    verificationTime);
            if (!parsed.IsSuccess
                || parsed.Receipt is null
                || !verified.IsSuccess
                || verified.Signer is null)
            {
                throw InvalidResult();
            }

            ArtifactSigningReceiptV1 receipt =
                parsed.Receipt;
            if (!FixedDigestEquals(
                    receipt.ReceiptSignerSpkiSha256,
                    verified.Signer
                        .SubjectPublicKeyInfoSha256)
                || expectedRequestId.HasValue
                    && receipt.RequestId
                        != expectedRequestId.Value
                || expectedRequestDigest is not null
                    && !FixedDigestEquals(
                        receipt.RequestDigest,
                        expectedRequestDigest)
                || receipt.CompletedAt > verificationTime)
            {
                throw InvalidResult();
            }

            ISigningProfile profile = profiles.Resolve(
                receipt.ProfileId,
                receipt.ProfileVersion);
            ValidateExactInventory(
                observed,
                profile.Descriptor);
            ValidateReceiptInventories(
                receipt,
                profile.Descriptor,
                read.Entries);
            return new CliVerifiedResult(
                receipt.RequestId,
                receipt.RequestDigest,
                receipt.ProjectId,
                receipt.ProfileId,
                receipt.ProfileVersion,
                receipt.SourceCommit,
                receipt.ReleaseVersion,
                SigningReceiptDigest.ComputeHex(
                    receiptJson),
                receipt.CompletedAt);
        }
        finally
        {
            CliFileSecurity.TryDeleteDirectory(
                temporaryDirectory);
        }
    }

    private static ReadOnlyCollection<ObservedEntry>
        InspectInventory(string path)
    {
        using FileStream archive = File.OpenRead(path);
        using TarReader reader = new(
            archive,
            leaveOpen: true);
        List<ObservedEntry> entries = [];
        HashSet<string> names =
            new(StringComparer.Ordinal);
        long total = 0;
        while (true)
        {
            TarEntry? entry;
            try
            {
                entry = reader.GetNextEntry(
                    copyData: false);
            }
            catch (Exception exception)
                when (exception is InvalidDataException
                    or EndOfStreamException)
            {
                throw InvalidResult();
            }

            if (entry is null)
            {
                break;
            }

            if (entries.Count
                    >= ClosedTarArchivePolicy.MaximumEntries
                || entry.Format is not TarEntryFormat.Ustar
                || entry.EntryType is not
                    TarEntryType.RegularFile
                || !IsAllowedShape(entry.Name)
                || !names.Add(entry.Name)
                || entry.Length is <= 0
                    or > ClosedTarArchivePolicy
                        .MaximumArchiveEntryBytes
                || entry.DataStream is null)
            {
                throw InvalidResult();
            }

            total = checked(total + entry.Length);
            if (total
                > ClosedTarArchivePolicy
                    .MaximumArchiveEntryBytes)
            {
                throw InvalidResult();
            }

            entry.DataStream.CopyTo(Stream.Null);
            entries.Add(new ObservedEntry(
                entry.Name,
                entry.Length));
        }

        return entries.AsReadOnly();
    }

    private static bool IsAllowedShape(string name)
    {
        if (name is ReceiptJsonName
            or ReceiptSignatureName)
        {
            return true;
        }

        return name.StartsWith(
                BundlePrefix,
                StringComparison.Ordinal)
            && name.Length > BundlePrefix.Length
            && name[BundlePrefix.Length..].Length <= 128
            && name[BundlePrefix.Length..].All(character =>
                char.IsAsciiLetterOrDigit(character)
                || character is '-' or '_' or '.')
            && name[^1] is not '.' and not ' ';
    }

    private static void ValidateExactInventory(
        IReadOnlyList<ObservedEntry> observed,
        SigningProfileDescriptor descriptor)
    {
        HashSet<string> expected =
        [
            ReceiptJsonName,
            ReceiptSignatureName,
        ];
        expected.UnionWith(descriptor.Artifacts
            .Where(item => item.Kind is not
                SigningProfileArtifactKind
                    .JsonBuildEvidence)
            .Select(item => string.Concat(
                BundlePrefix,
                item.FileName)));
        if (observed.Count != expected.Count
            || observed.Any(item =>
                !expected.Contains(item.Name)))
        {
            throw InvalidResult();
        }
    }

    private static void ValidateReceiptInventories(
        ArtifactSigningReceiptV1 receipt,
        SigningProfileDescriptor descriptor,
        IReadOnlyList<ClosedTarEntryResult> entries)
    {
        if (!descriptor.AllowedProjectIds.Contains(
                receipt.ProjectId,
                StringComparer.Ordinal)
            || !descriptor.AllowedSourceRepositories.Contains(
                receipt.SourceRepository,
                StringComparer.Ordinal)
            || !descriptor.AllowedSignerPolicyIds.Contains(
                receipt.SignerPolicyId,
                StringComparer.Ordinal)
            || !descriptor.AllowedTimestampPolicyIds.Contains(
                receipt.TimestampPolicyId,
                StringComparer.Ordinal))
        {
            throw InvalidResult();
        }

        SigningProfileArtifactDefinition[] results =
            descriptor.Artifacts
                .Where(item => item.Kind is not
                    SigningProfileArtifactKind
                        .JsonBuildEvidence)
                .ToArray();
        if (!HasExactArtifactIdentities(
                receipt.UnsignedArtifacts,
                descriptor.Artifacts)
            || !HasExactArtifactIdentities(
                receipt.ResultArtifacts,
                results))
        {
            throw InvalidResult();
        }

        Dictionary<string, SigningProfileArtifactDefinition>
            definitionsByRole = descriptor.Artifacts
                .ToDictionary(
                    item => item.Role,
                    StringComparer.Ordinal);
        if (receipt.UnsignedArtifacts.Any(item =>
                item.Size
                    > definitionsByRole[item.Role]
                        .MaximumBytes)
            || receipt.ResultArtifacts.Any(item =>
                item.Size
                    > definitionsByRole[item.Role]
                        .MaximumBytes))
        {
            throw InvalidResult();
        }

        Dictionary<string, ClosedTarEntryResult>
            files = entries.ToDictionary(
                item => item.Name,
                StringComparer.Ordinal);
        foreach (ReceiptArtifactV1 artifact
                 in receipt.ResultArtifacts)
        {
            ClosedTarEntryResult file =
                files[string.Concat(
                    BundlePrefix,
                    artifact.File)];
            if (file.Size != artifact.Size
                || !FixedDigestEquals(
                    file.Sha256,
                    artifact.Sha256))
            {
                throw InvalidResult();
            }
        }

        HashSet<(string Role, string File)>
            expectedAuthenticode = descriptor.Artifacts
                .Where(item => item.Kind is
                    SigningProfileArtifactKind
                        .PortableExecutable)
                .Select(item => (
                    item.Role,
                    File: item.FileName))
                .ToHashSet();
        HashSet<(string Role, string File)>
            actualAuthenticode = receipt
                .AuthenticodeArtifacts
                .Select(item => (
                    item.Role,
                    item.File))
                .ToHashSet();
        if (!expectedAuthenticode.SetEquals(
                actualAuthenticode))
        {
            throw InvalidResult();
        }
    }

    private static bool HasExactArtifactIdentities(
        IReadOnlyCollection<ReceiptArtifactV1> actual,
        IReadOnlyCollection<
            SigningProfileArtifactDefinition> expected)
    {
        HashSet<(string Role, string File)> actualSet =
            actual.Select(item => (
                    item.Role,
                    item.File))
                .ToHashSet();
        HashSet<(string Role, string File)> expectedSet =
            expected.Select(item => (
                    item.Role,
                    File: item.FileName))
                .ToHashSet();
        return actualSet.SetEquals(expectedSet);
    }

    private static string GetExtractionPath(
        string directory,
        string name)
    {
        return name.StartsWith(
                BundlePrefix,
                StringComparison.Ordinal)
            ? Path.Combine(
                directory,
                "bundle",
                name[BundlePrefix.Length..])
            : Path.Combine(directory, name);
    }

    private static void CreateOwnerOnlyDirectory(
        string path)
    {
        UnixFileMode mode =
            UnixFileMode.UserRead
            | UnixFileMode.UserWrite
            | UnixFileMode.UserExecute;
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(path);
        }
        else
        {
            Directory.CreateDirectory(path, mode);
        }
    }

    private static bool FixedDigestEquals(
        string left,
        string right)
    {
        return IsLowerSha256(left)
            && IsLowerSha256(right)
            && CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(left),
                Convert.FromHexString(right));
    }

    private static bool IsLowerSha256(string value)
    {
        return value.Length is 64
            && value.All(character =>
                character is >= '0' and <= '9'
                    or >= 'a' and <= 'f');
    }

    private static InvalidDataException InvalidResult()
    {
        return new InvalidDataException(
            "The signed result is invalid.");
    }

    private sealed record ObservedEntry(
        string Name,
        long Length);
}
