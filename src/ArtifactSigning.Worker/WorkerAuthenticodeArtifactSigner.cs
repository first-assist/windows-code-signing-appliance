using ArtifactSigning.Profiles;
using ArtifactSigning.Windows;

namespace ArtifactSigning.Worker;

public enum WorkerArtifactSigningError
{
    None,
    UnsignedInspectionFailed,
    SignToolFailed,
    SignedSnapshotInvalid,
    SignedVerificationFailed,
    ProviderMetadataFailed,
}

public sealed record WorkerArtifactSigningResult(
    VerifiedAuthenticodeArtifact? Evidence,
    string? TimestampAuthorityThumbprint,
    WorkerArtifactSigningError Error)
{
    public bool IsSuccess =>
        Error is WorkerArtifactSigningError.None
        && Evidence is not null
        && TimestampAuthorityThumbprint is not null;
}

public sealed class WorkerMicrosoftArtifactSigningArtifactSigner :
    IWorkerArtifactSigner
{
    private const string MetadataFileName = "metadata.json";

    private readonly IAuthenticodeFileVerifier _verifier;
    private readonly HashPinnedMicrosoftArtifactSignTool _signTool;
    private readonly MicrosoftArtifactSigningPolicy _signingPolicy;
    private readonly AuthenticodeTrustPolicy _trustPolicy;

    public WorkerMicrosoftArtifactSigningArtifactSigner(
        IAuthenticodeFileVerifier verifier,
        HashPinnedMicrosoftArtifactSignTool signTool,
        MicrosoftArtifactSigningPolicy signingPolicy,
        AuthenticodeTrustPolicy trustPolicy)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(signTool);
        ArgumentNullException.ThrowIfNull(signingPolicy);
        ArgumentNullException.ThrowIfNull(trustPolicy);
        if (trustPolicy.SignerTrustKind
            is not AuthenticodeSignerTrustKind
                .MicrosoftArtifactSigningPublisher)
        {
            throw new ArgumentException(
                "Managed signing requires Microsoft publisher trust.",
                nameof(trustPolicy));
        }

        _verifier = verifier;
        _signTool = signTool;
        _signingPolicy = signingPolicy;
        _trustPolicy = trustPolicy;
    }

    public async ValueTask<WorkerArtifactSigningResult> SignAndVerifyAsync(
        Guid trustedRequestId,
        string trustedWorkDirectory,
        string trustedRole,
        string trustedFileName,
        string trustedAbsoluteArtifactPath,
        long expectedUnsignedSize,
        string expectedUnsignedSha256,
        CancellationToken cancellationToken = default)
    {
        if (!HasExpectedProtectedLayout(
                trustedWorkDirectory,
                trustedAbsoluteArtifactPath,
                trustedFileName)
            || _verifier.VerifyUnsigned(
                trustedAbsoluteArtifactPath,
                expectedUnsignedSize,
                expectedUnsignedSha256)
                is not AuthenticodeVerificationError.None)
        {
            return Failure(
                WorkerArtifactSigningError.UnsignedInspectionFailed);
        }

        string metadataPath = Path.Combine(
            trustedWorkDirectory,
            MetadataFileName);
        bool metadataCreated = false;
        bool metadataRemoved = false;
        MicrosoftArtifactSigningExecutionResult? signingResult = null;
        try
        {
            byte[] metadata =
                MicrosoftArtifactSigningMetadataSerializer.Serialize(
                    _signingPolicy,
                    trustedRequestId,
                    trustedRole);
            using (FileStream stream = new(
                       metadataPath,
                       new FileStreamOptions
                       {
                           Mode = FileMode.CreateNew,
                           Access = FileAccess.Write,
                           Share = FileShare.None,
                           BufferSize = 4096,
                           Options = FileOptions.WriteThrough,
                       }))
            {
                metadataCreated = true;
                await stream.WriteAsync(metadata, cancellationToken)
                    .ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken)
                    .ConfigureAwait(false);
            }

            signingResult = await _signTool.SignAsync(
                    trustedAbsoluteArtifactPath,
                    expectedUnsignedSize,
                    expectedUnsignedSha256,
                    metadataPath,
                    trustedRequestId,
                    trustedRole,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (IOException)
        {
            return Failure(WorkerArtifactSigningError.ProviderMetadataFailed);
        }
        catch (UnauthorizedAccessException)
        {
            return Failure(WorkerArtifactSigningError.ProviderMetadataFailed);
        }
        finally
        {
            if (metadataCreated)
            {
                try
                {
                    File.Delete(metadataPath);
                    metadataRemoved = !File.Exists(metadataPath);
                }
                catch (IOException)
                {
                    metadataRemoved = false;
                }
                catch (UnauthorizedAccessException)
                {
                    metadataRemoved = false;
                }
            }
        }

        if (!metadataRemoved)
        {
            return Failure(WorkerArtifactSigningError.ProviderMetadataFailed);
        }

        if (signingResult?.IsSuccess is not true)
        {
            return Failure(WorkerArtifactSigningError.SignToolFailed);
        }

        if (!ArtifactFileSnapshot.TryCreate(
                trustedAbsoluteArtifactPath,
                out ArtifactFileSnapshot? signedSnapshot)
            || signedSnapshot is null)
        {
            return Failure(WorkerArtifactSigningError.SignedSnapshotInvalid);
        }

        AuthenticodeVerificationResult verification = _verifier.VerifySigned(
            trustedAbsoluteArtifactPath,
            signedSnapshot.Size,
            signedSnapshot.Sha256,
            _trustPolicy);
        if (!verification.IsSuccess || verification.Evidence is null)
        {
            return Failure(
                WorkerArtifactSigningError.SignedVerificationFailed);
        }

        return new WorkerArtifactSigningResult(
            VerifiedProfileEvidenceFactory.Create(
                trustedRole,
                trustedFileName,
                verification),
            verification.Evidence.TimestampAuthorityThumbprint,
            WorkerArtifactSigningError.None);
    }

    private static bool HasExpectedProtectedLayout(
        string trustedWorkDirectory,
        string trustedAbsoluteArtifactPath,
        string trustedFileName)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(trustedWorkDirectory)
                || !Path.IsPathFullyQualified(trustedWorkDirectory)
                || !string.Equals(
                    Path.GetFileName(trustedAbsoluteArtifactPath),
                    trustedFileName,
                    StringComparison.Ordinal))
            {
                return false;
            }

            string work = Path.TrimEndingDirectorySeparator(
                Path.GetFullPath(trustedWorkDirectory));
            string expectedArtifact = Path.GetFullPath(
                Path.Combine(
                    work,
                    WorkerReadyRecordOperation.BundleDirectoryName,
                    trustedFileName));
            FileAttributes workAttributes = File.GetAttributes(work);
            return workAttributes.HasFlag(FileAttributes.Directory)
                && !workAttributes.HasFlag(FileAttributes.ReparsePoint)
                && string.Equals(
                    expectedArtifact,
                    Path.GetFullPath(trustedAbsoluteArtifactPath),
                    StringComparison.OrdinalIgnoreCase)
                && !File.Exists(Path.Combine(work, MetadataFileName))
                && !Directory.Exists(Path.Combine(work, MetadataFileName));
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static WorkerArtifactSigningResult Failure(
        WorkerArtifactSigningError error)
    {
        return new WorkerArtifactSigningResult(null, null, error);
    }
}

public interface IWorkerArtifactSigner
{
    ValueTask<WorkerArtifactSigningResult> SignAndVerifyAsync(
        Guid trustedRequestId,
        string trustedWorkDirectory,
        string trustedRole,
        string trustedFileName,
        string trustedAbsoluteArtifactPath,
        long expectedUnsignedSize,
        string expectedUnsignedSha256,
        CancellationToken cancellationToken = default);
}

public sealed class WorkerAuthenticodeArtifactSigner : IWorkerArtifactSigner
{
    private readonly IAuthenticodeFileVerifier _verifier;
    private readonly HashPinnedSignTool _signTool;
    private readonly AuthenticodeTrustPolicy _trustPolicy;

    public WorkerAuthenticodeArtifactSigner(
        IAuthenticodeFileVerifier verifier,
        HashPinnedSignTool signTool,
        AuthenticodeTrustPolicy trustPolicy)
    {
        ArgumentNullException.ThrowIfNull(verifier);
        ArgumentNullException.ThrowIfNull(signTool);
        ArgumentNullException.ThrowIfNull(trustPolicy);
        _verifier = verifier;
        _signTool = signTool;
        _trustPolicy = trustPolicy;
    }

    public async ValueTask<WorkerArtifactSigningResult> SignAndVerifyAsync(
        Guid trustedRequestId,
        string trustedWorkDirectory,
        string trustedRole,
        string trustedFileName,
        string trustedAbsoluteArtifactPath,
        long expectedUnsignedSize,
        string expectedUnsignedSha256,
        CancellationToken cancellationToken = default)
    {
        _ = trustedRequestId;
        ArgumentException.ThrowIfNullOrWhiteSpace(trustedWorkDirectory);
        if (_verifier.VerifyUnsigned(
                trustedAbsoluteArtifactPath,
                expectedUnsignedSize,
                expectedUnsignedSha256)
            is not AuthenticodeVerificationError.None)
        {
            return Failure(
                WorkerArtifactSigningError.UnsignedInspectionFailed);
        }

        SignToolExecutionResult signingResult = await _signTool.SignAsync(
                trustedAbsoluteArtifactPath,
                expectedUnsignedSize,
                expectedUnsignedSha256,
                cancellationToken)
            .ConfigureAwait(false);
        if (!signingResult.IsSuccess)
        {
            return Failure(WorkerArtifactSigningError.SignToolFailed);
        }

        if (!ArtifactFileSnapshot.TryCreate(
                trustedAbsoluteArtifactPath,
                out ArtifactFileSnapshot? signedSnapshot)
            || signedSnapshot is null)
        {
            return Failure(WorkerArtifactSigningError.SignedSnapshotInvalid);
        }

        AuthenticodeVerificationResult verification = _verifier.VerifySigned(
            trustedAbsoluteArtifactPath,
            signedSnapshot.Size,
            signedSnapshot.Sha256,
            _trustPolicy);
        if (!verification.IsSuccess)
        {
            return Failure(
                WorkerArtifactSigningError.SignedVerificationFailed);
        }

        VerifiedAuthenticodeFile windowsEvidence = verification.Evidence!;
        return new WorkerArtifactSigningResult(
            VerifiedProfileEvidenceFactory.Create(
                trustedRole,
                trustedFileName,
                verification),
            windowsEvidence.TimestampAuthorityThumbprint,
            WorkerArtifactSigningError.None);
    }

    private static WorkerArtifactSigningResult Failure(
        WorkerArtifactSigningError error)
    {
        return new WorkerArtifactSigningResult(null, null, error);
    }
}
