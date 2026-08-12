using System.Security.Cryptography;
using ArtifactSigning.Protocol;

namespace ArtifactSigning.Gateway;

public sealed record GatewayVerifiedWorkerAuditAnchor(
    WorkerAuditAnchorV1 Anchor,
    ReadOnlyMemory<byte> AnchorJson,
    ReadOnlyMemory<byte> AnchorSignature);

public sealed class GatewayAuditAnchorReader
{
    private readonly GatewayDirectoryLayout _layout;
    private readonly CmsTrustPolicy _receiptTrust;

    public GatewayAuditAnchorReader(
        GatewayDirectoryLayout layout,
        CmsTrustPolicy receiptTrust)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(receiptTrust);
        _layout = layout;
        _receiptTrust = receiptTrust;
    }

    public GatewayVerifiedWorkerAuditAnchor ReadCurrent(
        DateTimeOffset verificationTime)
    {
        GatewayContractRules.ValidateTimestamp(
            verificationTime,
            nameof(verificationTime));
        Dictionary<string, string> jsonFiles = [];
        Dictionary<string, string> signatureFiles = [];
        foreach (string path in Directory.EnumerateFiles(
                     _layout.WorkerStatusRoot,
                     string.Concat(
                         WorkerAuditAnchorFiles.FilePrefix,
                         "*"),
                     SearchOption.TopDirectoryOnly))
        {
            string name = Path.GetFileName(path);
            if (WorkerAuditAnchorFiles.TryParseJsonFileName(
                    name,
                    out string jsonDigest))
            {
                if (!jsonFiles.TryAdd(jsonDigest, path))
                {
                    throw InvalidAnchor();
                }

                continue;
            }

            if (WorkerAuditAnchorFiles
                .TryParseSignatureFileName(
                    name,
                    out string signatureDigest))
            {
                if (!signatureFiles.TryAdd(
                        signatureDigest,
                        path))
                {
                    throw InvalidAnchor();
                }

                continue;
            }

            throw InvalidAnchor();
        }

        if (jsonFiles.Count is 0
            || jsonFiles.Count
                > WorkerAuditAnchorFiles
                    .MaximumRetainedAnchors
            || !jsonFiles.Keys.ToHashSet(
                    StringComparer.Ordinal)
                .SetEquals(signatureFiles.Keys))
        {
            throw InvalidAnchor();
        }

        List<GatewayVerifiedWorkerAuditAnchor>
            verified = [];
        foreach ((string digest, string jsonPath)
                 in jsonFiles)
        {
            byte[] json = ReadBounded(
                jsonPath,
                WorkerAuditAnchorJson
                    .MaximumAnchorJsonBytes);
            if (!FixedDigestEquals(
                    digest,
                    Convert.ToHexStringLower(
                        SHA256.HashData(json))))
            {
                throw InvalidAnchor();
            }

            byte[] signature = ReadBounded(
                signatureFiles[digest],
                WorkerAuditAnchorFiles
                    .MaximumSignatureBytes);
            WorkerAuditAnchorJsonParseResult parsed =
                WorkerAuditAnchorJson.Parse(json);
            TrustedDetachedCmsVerificationResult cms =
                TrustedDetachedCmsSignatureVerifier.Verify(
                    json,
                    signature,
                    _receiptTrust,
                    verificationTime);
            if (!parsed.IsSuccess
                || parsed.Anchor is null
                || !cms.IsSuccess
                || cms.Signer is null
                || !FixedDigestEquals(
                    parsed.Anchor
                        .ReceiptSignerSpkiSha256,
                    cms.Signer
                        .SubjectPublicKeyInfoSha256)
                || parsed.Anchor.PublishedAt
                    > verificationTime)
            {
                throw InvalidAnchor();
            }

            verified.Add(
                new GatewayVerifiedWorkerAuditAnchor(
                    parsed.Anchor,
                    json,
                    signature));
        }

        GatewayVerifiedWorkerAuditAnchor[] ordered =
            verified.OrderBy(item =>
                    item.Anchor.PublishedAt)
                .ThenBy(item =>
                    item.Anchor.WorkerSequence)
                .ToArray();
        for (int index = 1;
             index < ordered.Length;
             index++)
        {
            WorkerAuditAnchorV1 previous =
                ordered[index - 1].Anchor;
            WorkerAuditAnchorV1 current =
                ordered[index].Anchor;
            if (current.PublishedAt
                    == previous.PublishedAt
                && current.WorkerSequence
                    == previous.WorkerSequence
                || current.WorkerSequence
                    < previous.WorkerSequence
                || current.WorkerSequence
                    == previous.WorkerSequence
                    && !FixedDigestEquals(
                        current.WorkerEventDigest,
                        previous.WorkerEventDigest))
            {
                throw InvalidAnchor();
            }
        }

        GatewayVerifiedWorkerAuditAnchor latest =
            ordered[^1];
        if (verificationTime
            >= latest.Anchor.ExpiresAt)
        {
            throw InvalidAnchor();
        }

        return latest;
    }

    private static byte[] ReadBounded(
        string path,
        int maximumBytes)
    {
        using FileStream input =
            GatewayDirectFile.OpenRead(path);
        if (input.Length is <= 0
            || input.Length > maximumBytes)
        {
            throw InvalidAnchor();
        }

        byte[] content =
            new byte[checked((int)input.Length)];
        input.ReadExactly(content);
        return content;
    }

    private static bool FixedDigestEquals(
        string left,
        string right)
    {
        return GatewayContractRules.IsLowerHex(left, 64)
            && GatewayContractRules.IsLowerHex(right, 64)
            && CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(left),
                Convert.FromHexString(right));
    }

    private static InvalidDataException InvalidAnchor()
    {
        return new InvalidDataException(
            "Worker audit anchor is invalid.");
    }
}

public sealed class GatewayReadinessProbe
{
    public const string RequiredWorkerVersion = "0.11.2";

    private readonly GatewayStateStore _stateStore;
    private readonly GatewayAuditAnchorReader _anchorReader;
    private readonly Action? _installedSecurityValidation;
    private readonly TimeProvider _timeProvider;

    public GatewayReadinessProbe(
        GatewayStateStore stateStore,
        GatewayAuditAnchorReader anchorReader,
        Action? installedSecurityValidation = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(stateStore);
        ArgumentNullException.ThrowIfNull(anchorReader);
        _stateStore = stateStore;
        _anchorReader = anchorReader;
        _installedSecurityValidation =
            installedSecurityValidation;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public bool IsReady()
    {
        try
        {
            _installedSecurityValidation?.Invoke();
            _stateStore.Layout.ValidateExistingRoots();
            _ = _stateStore.GetAuditHead();
            GatewayVerifiedWorkerAuditAnchor worker =
                _anchorReader.ReadCurrent(
                    WholeSecondNow());
            return worker.Anchor.WorkerReady
                && worker.Anchor.TimestampDependencyReady
                && string.Equals(
                    worker.Anchor.WorkerVersion,
                    RequiredWorkerVersion,
                    StringComparison.Ordinal);
        }
        catch (Exception exception)
            when (exception is not OutOfMemoryException)
        {
            return false;
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
