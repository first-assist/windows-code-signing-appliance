using System.Security.Cryptography;
using ArtifactSigning.Protocol;

namespace ArtifactSigning.Worker;

public interface IWorkerReadinessDependencyProbe
{
    bool IsTimestampDependencyReady();
}

public interface IWorkerAuditAnchorPublisher
{
    bool Publish(bool workerReady);
}

public sealed class WorkerAuditAnchorPublisher :
    IWorkerAuditAnchorPublisher
{
    public const string WorkerVersion = "0.11.2";
    public static readonly TimeSpan AnchorLifetime =
        TimeSpan.FromMinutes(2);

    private readonly WorkerStateStore _stateStore;
    private readonly WorkerReceiptCmsSigner _signer;
    private readonly IWorkerReadinessDependencyProbe
        _dependencyProbe;
    private readonly TimeProvider _timeProvider;

    public WorkerAuditAnchorPublisher(
        WorkerStateStore stateStore,
        WorkerReceiptCmsSigner signer,
        IWorkerReadinessDependencyProbe dependencyProbe,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(stateStore);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(dependencyProbe);
        _stateStore = stateStore;
        _signer = signer;
        _dependencyProbe = dependencyProbe;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public bool Publish(bool workerReady)
    {
        try
        {
            DateTimeOffset now = WholeSecondNow();
            AuditHeadV1 head = _stateStore.GetAuditHead();
            bool timestampReady =
                _dependencyProbe
                    .IsTimestampDependencyReady();
            WorkerAuditAnchorV1 anchor = new(
                head.Sequence,
                head.EventDigest,
                WorkerVersion,
                workerReady,
                timestampReady,
                now,
                now.Add(AnchorLifetime),
                _signer.SubjectPublicKeyInfoSha256);
            byte[] json =
                WorkerAuditAnchorJson.Serialize(anchor);
            WorkerReceiptSigningResult signed =
                _signer.SignAndVerify(json, now);
            if (!signed.IsSuccess)
            {
                return false;
            }

            byte[] signature = signed.GetSignatureBytes();
            if (signature.Length
                > WorkerAuditAnchorFiles
                    .MaximumSignatureBytes)
            {
                return false;
            }

            string digest = Convert.ToHexStringLower(
                SHA256.HashData(json));
            PublishPair(digest, json, signature);
            TrimRetainedAnchors(digest);
            return true;
        }
        catch (Exception exception)
            when (exception is IOException
                or UnauthorizedAccessException
                or InvalidDataException
                or ArgumentException
                or InvalidOperationException
                or CryptographicException
                or NotSupportedException)
        {
            return false;
        }
    }

    private void PublishPair(
        string digest,
        byte[] json,
        byte[] signature)
    {
        string root =
            _stateStore.Layout.GatewayStatusRoot;
        string jsonPath = Path.Combine(
            root,
            WorkerAuditAnchorFiles.GetJsonFileName(digest));
        string signaturePath = Path.Combine(
            root,
            WorkerAuditAnchorFiles
                .GetSignatureFileName(digest));
        string jsonTemporary = string.Concat(
            jsonPath,
            ".worker-new");
        string signatureTemporary = string.Concat(
            signaturePath,
            ".worker-new");
        EnsurePublished(
            signatureTemporary,
            signaturePath,
            signature);
        EnsurePublished(
            jsonTemporary,
            jsonPath,
            json);
    }

    private static void EnsurePublished(
        string temporaryPath,
        string destinationPath,
        byte[] content)
    {
        if (File.Exists(destinationPath))
        {
            RequireExactExisting(
                destinationPath,
                content);
            if (File.Exists(temporaryPath))
            {
                RequireExactExisting(
                    temporaryPath,
                    content);
                File.Delete(temporaryPath);
            }

            return;
        }

        if (File.Exists(temporaryPath))
        {
            RequireExactExisting(
                temporaryPath,
                content);
        }
        else
        {
            WriteNew(temporaryPath, content);
        }

        File.Move(
            temporaryPath,
            destinationPath);
    }

    private static void WriteNew(
        string path,
        byte[] content)
    {
        using FileStream output = new(
            path,
            new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                BufferSize = 4096,
                Options = FileOptions.WriteThrough,
            });
        output.Write(content);
        output.Flush(flushToDisk: true);
    }

    private static void RequireExactExisting(
        string path,
        byte[] expected)
    {
        using FileStream input =
            WorkerDirectFile.OpenRead(path);
        if (input.Length != expected.Length)
        {
            throw new InvalidDataException(
                "Published audit anchor conflicts.");
        }

        byte[] actual = new byte[expected.Length];
        input.ReadExactly(actual);
        if (!actual.AsSpan().SequenceEqual(expected))
        {
            throw new InvalidDataException(
                "Published audit anchor conflicts.");
        }
    }

    private void TrimRetainedAnchors(
        string currentDigest)
    {
        string root =
            _stateStore.Layout.GatewayStatusRoot;
        FileInfo[] anchors = Directory
            .EnumerateFiles(
                root,
                string.Concat(
                    WorkerAuditAnchorFiles.FilePrefix,
                    "*",
                    WorkerAuditAnchorFiles.JsonSuffix),
                SearchOption.TopDirectoryOnly)
            .Select(path => new FileInfo(path))
            .OrderByDescending(item =>
                item.LastWriteTimeUtc)
            .ThenByDescending(
                item => item.Name,
                StringComparer.Ordinal)
            .ToArray();
        foreach (FileInfo obsolete in anchors
                     .Where(item => !string.Equals(
                         item.Name,
                         WorkerAuditAnchorFiles
                             .GetJsonFileName(
                                 currentDigest),
                         StringComparison.Ordinal))
                     .Skip(
                         WorkerAuditAnchorFiles
                             .MaximumRetainedAnchors - 1))
        {
            if (!WorkerAuditAnchorFiles.TryParseJsonFileName(
                    obsolete.Name,
                    out string digest))
            {
                continue;
            }

            TryDelete(obsolete.FullName);
            TryDelete(Path.Combine(
                root,
                WorkerAuditAnchorFiles
                    .GetSignatureFileName(digest)));
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
            // The next publication retries bounded retention.
        }
        catch (UnauthorizedAccessException)
        {
            // The next publication retries bounded retention.
        }
    }

    private DateTimeOffset WholeSecondNow()
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
}
