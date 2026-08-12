using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using ArtifactSigning.Profiles;
using ArtifactSigning.Protocol;

namespace ArtifactSigning.Worker;

public sealed class WorkerReadyRecordOperation :
    IWorkerJobRevalidator,
    IWorkerSigningOperation
{
    public const string RequestJsonFileName = "request.json";
    public const string RequestSignatureFileName = "request.p7s";
    public const string ApprovalSignatureFileName = "approval.p7s";
    public const string BundleDirectoryName = "bundle";
    public const string UnsignedSnapshotDirectoryName = "unsigned";
    public const string ReceiptJsonFileName = "signing-receipt.json";
    public const string ReceiptSignatureFileName = "signing-receipt.p7s";

    private const int MaximumAuthorizationPolicies = 32;
    private const int MaximumSigningPolicies = 16;

    private readonly WorkerStateStore _stateStore;
    private readonly SigningProfileRegistry _profileRegistry;
    private readonly IReadOnlyList<WorkerAuthorizationPolicy>
        _authorizationPolicies;
    private readonly IReadOnlyList<WorkerInstalledSigningPolicy>
        _signingPolicies;
    private readonly WorkerReceiptCmsSigner _receiptSigner;
    private readonly TimeProvider _timeProvider;
    private readonly string _workerVersion;

    public WorkerReadyRecordOperation(
        WorkerStateStore stateStore,
        SigningProfileRegistry profileRegistry,
        IEnumerable<WorkerAuthorizationPolicy> authorizationPolicies,
        IEnumerable<WorkerInstalledSigningPolicy> signingPolicies,
        WorkerReceiptCmsSigner receiptSigner,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(stateStore);
        ArgumentNullException.ThrowIfNull(profileRegistry);
        ArgumentNullException.ThrowIfNull(authorizationPolicies);
        ArgumentNullException.ThrowIfNull(signingPolicies);
        ArgumentNullException.ThrowIfNull(receiptSigner);

        WorkerAuthorizationPolicy[] authorizations =
            authorizationPolicies.ToArray();
        WorkerInstalledSigningPolicy[] installedSigningPolicies =
            signingPolicies.ToArray();
        if (authorizations.Length is 0 or > MaximumAuthorizationPolicies
            || authorizations.Any(policy => policy is null)
            || installedSigningPolicies.Length is 0
                or > MaximumSigningPolicies
            || installedSigningPolicies.Any(policy => policy is null))
        {
            throw new ArgumentException(
                "Worker installed policies are empty, oversized, or invalid.");
        }

        if (authorizations
                .Select(policy => (
                    policy.ProjectId,
                    policy.ProfileId,
                    policy.ProfileVersion,
                    policy.SubmitterTrustPolicy.ExpectedSignerSpkiSha256,
                    policy.ApproverTrustPolicy.ExpectedSignerSpkiSha256))
                .Distinct()
                .Count()
            != authorizations.Length
            || installedSigningPolicies
                .Select(policy => (
                    policy.SignerPolicyId,
                    policy.TimestampPolicyId))
                .Distinct()
                .Count()
            != installedSigningPolicies.Length)
        {
            throw new ArgumentException(
                "Worker installed policy registrations must be unique.");
        }

        foreach (WorkerAuthorizationPolicy authorization in authorizations)
        {
            ISigningProfile? profile = profileRegistry.Resolve(
                authorization.ProfileId,
                authorization.ProfileVersion);
            if (profile is null
                || !profile.Descriptor.AllowedProjectIds.Contains(
                    authorization.ProjectId,
                    StringComparer.Ordinal)
                || !installedSigningPolicies.Any(policy =>
                    profile.Descriptor.AllowedSignerPolicyIds.Contains(
                        policy.SignerPolicyId,
                        StringComparer.Ordinal)
                    && profile.Descriptor.AllowedTimestampPolicyIds.Contains(
                        policy.TimestampPolicyId,
                        StringComparer.Ordinal)))
            {
                throw new ArgumentException(
                    "Worker authorization references an uninstalled profile.");
            }
        }

        if (installedSigningPolicies.Any(policy =>
                policy.Provider
                    is WorkerSigningProvider.LocalMachineCertificate
                && (string.Equals(
                        policy.SignerThumbprint,
                        receiptSigner.CertificateThumbprint,
                        StringComparison.Ordinal)
                    || string.Equals(
                        policy.SignerSpkiSha256,
                        receiptSigner.SubjectPublicKeyInfoSha256,
                        StringComparison.Ordinal))))
        {
            throw new ArgumentException(
                "Receipt and Authenticode identities must be distinct.");
        }

        _stateStore = stateStore;
        _profileRegistry = profileRegistry;
        _authorizationPolicies = Array.AsReadOnly(authorizations);
        _signingPolicies = Array.AsReadOnly(installedSigningPolicies);
        _receiptSigner = receiptSigner;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _workerVersion = GetWorkerVersion();
    }

    public ValueTask<WorkerRevalidationResult> RevalidateAsync(
        WorkerJobRecord job,
        string trustedWorkDirectory,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(job);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            ReadyRecordLoadResult load = LoadAndValidateReadyRecord(
                job,
                trustedWorkDirectory,
                GetWholeSecondUtcNow());
            return ValueTask.FromResult(
                load.Error switch
                {
                    ReadyRecordError.None =>
                        WorkerRevalidationResult.Success,
                    ReadyRecordError.RequestExpired =>
                        new WorkerRevalidationResult(
                            WorkerRevalidationError.RequestExpired),
                    ReadyRecordError.AuthorizationInvalid =>
                        new WorkerRevalidationResult(
                            WorkerRevalidationError.AuthorizationInvalid),
                    ReadyRecordError.ProfileInvalid =>
                        new WorkerRevalidationResult(
                            WorkerRevalidationError.ProfileInvalid),
                    ReadyRecordError.ApprovalInvalid =>
                        new WorkerRevalidationResult(
                            WorkerRevalidationError.ApprovalInvalid),
                    _ => new WorkerRevalidationResult(
                        WorkerRevalidationError.RequestInvalid),
                });
        }
        catch (Exception exception)
            when (exception is not OutOfMemoryException)
        {
            return ValueTask.FromResult(
                new WorkerRevalidationResult(
                    WorkerRevalidationError.RequestInvalid));
        }
    }

    public async ValueTask<WorkerSigningOperationResult> ExecuteAsync(
        WorkerJobRecord signingJob,
        string trustedWorkDirectory,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(signingJob);
        cancellationToken.ThrowIfCancellationRequested();

        ReadyRecordLoadResult load;
        try
        {
            load = LoadAndValidateReadyRecord(
                signingJob,
                trustedWorkDirectory,
                GetWholeSecondUtcNow());
        }
        catch (Exception exception)
            when (exception is not OutOfMemoryException)
        {
            return WorkerSigningOperationResult.Failed(
                WorkerSigningFailure.ReadyRecordInvalid);
        }

        if (!load.IsSuccess)
        {
            return WorkerSigningOperationResult.Failed(
                load.Error is ReadyRecordError.AuthorizationInvalid
                    or ReadyRecordError.ApprovalInvalid
                    ? WorkerSigningFailure.AuthorizationInvalid
                    : WorkerSigningFailure.ReadyRecordInvalid);
        }

        ValidatedReadyRecord ready = load.Record!;
        string bundleDirectory = Path.Combine(
            trustedWorkDirectory,
            BundleDirectoryName);
        string unsignedDirectory = Path.Combine(
            trustedWorkDirectory,
            UnsignedSnapshotDirectoryName);

        try
        {
            if (!TryCreateUnsignedSnapshot(
                    ready,
                    bundleDirectory,
                    unsignedDirectory))
            {
                return Failure(
                    WorkerSigningFailure.ArtifactPrecheckFailed);
            }

            WorkerProfileArtifactReader unsignedReader = new(
                unsignedDirectory,
                ready.Profile.Descriptor);
            SigningProfileValidationResult snapshotValidation =
                ready.Profile.ValidateUnsignedBundle(
                    new SigningProfileValidationContext(
                        ready.Request,
                        unsignedReader,
                        GetWholeSecondUtcNow()));
            if (!snapshotValidation.IsSuccess)
            {
                return Failure(
                    WorkerSigningFailure.ArtifactPrecheckFailed);
            }

            List<SignedWorkerArtifact> signedArtifacts = [];
            foreach (SigningProfileArtifactDefinition definition
                     in ready.Profile.Descriptor.Artifacts)
            {
                if (definition.Kind
                    is not SigningProfileArtifactKind.PortableExecutable)
                {
                    continue;
                }

                cancellationToken.ThrowIfCancellationRequested();
                RequestArtifactV1 requestArtifact = ready.Request.Artifacts
                    .Single(artifact => string.Equals(
                        artifact.Role,
                        definition.Role,
                        StringComparison.Ordinal));
                string artifactPath = Path.Combine(
                    bundleDirectory,
                    definition.FileName);
                WorkerArtifactSigningResult signingResult =
                    await ready.SigningPolicy.ArtifactSigner
                        .SignAndVerifyAsync(
                            ready.Request.RequestId,
                            trustedWorkDirectory,
                            definition.Role,
                            definition.FileName,
                            artifactPath,
                            requestArtifact.Size,
                            requestArtifact.Sha256,
                            cancellationToken)
                        .ConfigureAwait(false);
                if (!signingResult.IsSuccess
                    || signingResult.Evidence is null
                    || signingResult.TimestampAuthorityThumbprint is null
                    || !EvidenceMatchesPolicy(
                        signingResult,
                        definition,
                        ready.SigningPolicy))
                {
                    return Failure(
                        MapArtifactSigningFailure(signingResult));
                }

                signedArtifacts.Add(
                    new SignedWorkerArtifact(
                        signingResult.Evidence,
                        signingResult.TimestampAuthorityThumbprint));
            }

            if (signedArtifacts.Count is 0)
            {
                return Failure(
                    WorkerSigningFailure.ProfileFinalizationFailed);
            }

            DateTimeOffset finalizedAt = GetWholeSecondUtcNow();
            WorkerProfileArtifactReader signedReader = new(
                bundleDirectory,
                ready.Profile.Descriptor);
            SigningProfileFinalizationResult finalization =
                ready.Profile.FinalizeSignedBundle(
                    new SigningProfileFinalizationContext(
                        ready.Request,
                        unsignedReader,
                        signedReader,
                        signedArtifacts.Select(item => item.Evidence),
                        finalizedAt));
            if (!finalization.IsSuccess
                || !TryWriteFileAtomically(
                    Path.Combine(
                        bundleDirectory,
                        GetManifestDefinition(
                            ready.Profile.Descriptor).FileName),
                    finalization.GetFinalizedManifestBytes(),
                    overwrite: true))
            {
                return Failure(
                    WorkerSigningFailure.ProfileFinalizationFailed);
            }

            SigningProfileValidationResult finalizedValidation =
                ready.Profile.ValidateFinalizedBundle(
                    new SigningProfileFinalizedValidationContext(
                        ready.Request,
                        signedReader,
                        signedArtifacts.Select(item => item.Evidence),
                        GetWholeSecondUtcNow()));
            if (!finalizedValidation.IsSuccess)
            {
                return Failure(
                    WorkerSigningFailure.FinalizedValidationFailed);
            }

            DateTimeOffset completedAt = GetWholeSecondUtcNow();
            if (completedAt >= ready.Request.ExpiresAt)
            {
                return Failure(
                    WorkerSigningFailure.ProfileFinalizationFailed);
            }

            WorkerJobRecord? current =
                _stateStore.GetJob(signingJob.RequestId);
            if (current is null
                || current.State is not RequestState.Signing
                || current.RowVersion != signingJob.RowVersion
                || !string.Equals(
                    current.RequestDigest,
                    signingJob.RequestDigest,
                    StringComparison.Ordinal))
            {
                return Failure(
                    WorkerSigningFailure.ReadyRecordInvalid);
            }

            ArtifactSigningReceiptV1 receipt = CreateReceipt(
                ready,
                signedArtifacts,
                bundleDirectory,
                _stateStore.GetLatestAuditSequence(
                    signingJob.RequestId),
                completedAt);
            byte[] receiptJson =
                ArtifactSigningReceiptJsonSerializer.Serialize(receipt);
            WorkerReceiptSigningResult receiptSignature =
                _receiptSigner.SignAndVerify(
                    receiptJson,
                    completedAt);
            byte[] receiptSignatureBytes = receiptSignature.IsSuccess
                ? receiptSignature.GetSignatureBytes()
                : [];
            if (!receiptSignature.IsSuccess
                || !TryWriteFileAtomically(
                    Path.Combine(
                        trustedWorkDirectory,
                        ReceiptJsonFileName),
                    receiptJson,
                    overwrite: false)
                || !TryWriteFileAtomically(
                    Path.Combine(
                        trustedWorkDirectory,
                        ReceiptSignatureFileName),
                    receiptSignatureBytes,
                    overwrite: false))
            {
                return Failure(
                    WorkerSigningFailure.ReceiptSigningFailed);
            }

            if (!TryCloseResultInventory(
                    ready.Profile.Descriptor,
                    trustedWorkDirectory,
                    unsignedDirectory,
                    bundleDirectory)
                || !ValidateResultInventory(
                    ready.Profile.Descriptor,
                    trustedWorkDirectory,
                    bundleDirectory,
                    receipt,
                    receiptJson,
                    receiptSignatureBytes))
            {
                return Failure(
                    WorkerSigningFailure.OutputPreparationFailed);
            }

            return WorkerSigningOperationResult.Success(
                SigningReceiptDigest.ComputeHex(receiptJson));
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
            when (exception is not OutOfMemoryException)
        {
            return Failure(WorkerSigningFailure.OutputPreparationFailed);
        }
    }

    private ReadyRecordLoadResult LoadAndValidateReadyRecord(
        WorkerJobRecord job,
        string trustedWorkDirectory,
        DateTimeOffset verificationTime)
    {
        if (job.State is not (RequestState.Approved or RequestState.Signing)
            || !ValidateInitialInventoryRoot(trustedWorkDirectory))
        {
            return ReadyRecordLoadResult.Failure(
                ReadyRecordError.InventoryInvalid);
        }

        byte[] requestJson = WorkerDirectFile.ReadBounded(
            Path.Combine(trustedWorkDirectory, RequestJsonFileName),
            ArtifactSigningRequestJsonParser.MaximumRequestJsonBytes);
        byte[] requestSignature = WorkerDirectFile.ReadBounded(
            Path.Combine(
                trustedWorkDirectory,
                RequestSignatureFileName),
            DetachedCmsSignatureVerifier.MaximumSignatureBytes);
        byte[] approvalSignature = WorkerDirectFile.ReadBounded(
            Path.Combine(
                trustedWorkDirectory,
                ApprovalSignatureFileName),
            DetachedCmsSignatureVerifier.MaximumSignatureBytes);

        RequestJsonParseResult requestResult =
            ArtifactSigningRequestJsonParser.Parse(requestJson);
        if (!requestResult.IsSuccess || requestResult.Request is null)
        {
            return ReadyRecordLoadResult.Failure(
                ReadyRecordError.RequestInvalid);
        }

        ArtifactSigningRequestV1 request = requestResult.Request;
        string requestDigest = RequestDigest.ComputeHex(requestJson);
        if (request.RequestId != job.RequestId
            || !FixedTimeDigestEquals(requestDigest, job.RequestDigest))
        {
            return ReadyRecordLoadResult.Failure(
                ReadyRecordError.RequestInvalid);
        }

        if (verificationTime < request.RequestedAt
            || verificationTime >= request.ExpiresAt)
        {
            return ReadyRecordLoadResult.Failure(
                ReadyRecordError.RequestExpired);
        }

        ISigningProfile? profile = _profileRegistry.Resolve(
            request.ProfileId,
            request.ProfileVersion);
        if (profile is null
            || !ValidateBundleInventory(
                Path.Combine(
                    trustedWorkDirectory,
                    BundleDirectoryName),
                profile.Descriptor))
        {
            return ReadyRecordLoadResult.Failure(
                ReadyRecordError.ProfileInvalid);
        }

        WorkerInstalledSigningPolicy? signingPolicy =
            _signingPolicies.SingleOrDefault(policy => policy.Matches(
                request.SignerPolicyId,
                request.TimestampPolicyId));
        if (signingPolicy is null)
        {
            return ReadyRecordLoadResult.Failure(
                ReadyRecordError.ProfileInvalid);
        }

        AuthorizedSigners? authorized = VerifyAuthorization(
            request,
            requestDigest,
            requestJson,
            requestSignature,
            approvalSignature,
            verificationTime);
        if (authorized is null)
        {
            return ReadyRecordLoadResult.Failure(
                ReadyRecordError.AuthorizationInvalid);
        }

        WorkerProfileArtifactReader reader = new(
            Path.Combine(
                trustedWorkDirectory,
                BundleDirectoryName),
            profile.Descriptor);
        SigningProfileValidationResult validation =
            profile.ValidateUnsignedBundle(
                new SigningProfileValidationContext(
                    request,
                    reader,
                    verificationTime));
        if (!validation.IsSuccess)
        {
            return ReadyRecordLoadResult.Failure(
                ReadyRecordError.ProfileInvalid);
        }

        return ReadyRecordLoadResult.Success(
            new ValidatedReadyRecord(
                request,
                requestDigest,
                profile,
                signingPolicy,
                authorized.Submitter,
                authorized.Approver));
    }

    private AuthorizedSigners? VerifyAuthorization(
        ArtifactSigningRequestV1 request,
        string requestDigest,
        ReadOnlyMemory<byte> requestJson,
        ReadOnlyMemory<byte> requestSignature,
        ReadOnlyMemory<byte> approvalSignature,
        DateTimeOffset verificationTime)
    {
        foreach (WorkerAuthorizationPolicy policy
                 in _authorizationPolicies.Where(policy => policy.Matches(
                     request.ProjectId,
                     request.ProfileId,
                     request.ProfileVersion)))
        {
            TrustedDetachedCmsVerificationResult submitter =
                TrustedDetachedCmsSignatureVerifier.Verify(
                    requestJson,
                    requestSignature,
                    policy.SubmitterTrustPolicy,
                    verificationTime);
            if (!submitter.IsSuccess || submitter.Signer is null)
            {
                continue;
            }

            TrustedAttachedCmsVerificationResult approver =
                TrustedAttachedCmsSignatureVerifier.Verify(
                    approvalSignature,
                    policy.ApproverTrustPolicy,
                    verificationTime,
                    ArtifactSigningApprovalJsonParser
                        .MaximumApprovalJsonBytes);
            if (!approver.IsSuccess || approver.Signer is null)
            {
                continue;
            }

            ApprovalJsonParseResult approvalResult =
                ArtifactSigningApprovalJsonParser.Parse(
                    approver.GetContentBytes());
            if (!approvalResult.IsSuccess
                || approvalResult.Approval is null
                || approvalResult.Approval.Decision
                    is not ApprovalDecision.Approve
                || ApprovalBinding.Validate(
                    approvalResult.Approval,
                    request.RequestId,
                    requestDigest,
                    verificationTime)
                    is not ApprovalBindingError.None
                || policy.RequireDistinctSubmitterAndApprover
                    && string.Equals(
                        submitter.Signer.SubjectPublicKeyInfoSha256,
                        approver.Signer.SubjectPublicKeyInfoSha256,
                        StringComparison.Ordinal))
            {
                continue;
            }

            return new AuthorizedSigners(
                submitter.Signer,
                approver.Signer);
        }

        return null;
    }

    private ArtifactSigningReceiptV1 CreateReceipt(
        ValidatedReadyRecord ready,
        IReadOnlyList<SignedWorkerArtifact> signedArtifacts,
        string bundleDirectory,
        ulong signingAuditSequence,
        DateTimeOffset completedAt)
    {
        Dictionary<string, RequestArtifactV1> requestByRole =
            ready.Request.Artifacts.ToDictionary(
                artifact => artifact.Role,
                StringComparer.Ordinal);
        List<ReceiptArtifactV1> unsigned = ready.Profile.Descriptor.Artifacts
            .Select(definition =>
            {
                RequestArtifactV1 artifact =
                    requestByRole[definition.Role];
                return new ReceiptArtifactV1(
                    definition.Role,
                    definition.FileName,
                    artifact.Size,
                    artifact.Sha256);
            })
            .ToList();
        List<ReceiptArtifactV1> results = ready.Profile.Descriptor.Artifacts
            .Where(definition =>
                definition.Kind
                    is not SigningProfileArtifactKind.JsonBuildEvidence)
            .Select(definition => ReadReceiptArtifact(
                definition,
                bundleDirectory))
            .ToList();
        Dictionary<string, SignedWorkerArtifact> evidenceByRole =
            signedArtifacts.ToDictionary(
                artifact => artifact.Evidence.Role,
                StringComparer.Ordinal);
        List<ReceiptAuthenticodeArtifactV1> authenticode =
            ready.Profile.Descriptor.Artifacts
                .Where(definition =>
                    definition.Kind
                        is SigningProfileArtifactKind.PortableExecutable)
                .Select(definition =>
                {
                    SignedWorkerArtifact signed =
                        evidenceByRole[definition.Role];
                    return new ReceiptAuthenticodeArtifactV1(
                        definition.Role,
                        definition.FileName,
                        requestByRole[definition.Role].Sha256,
                        signed.Evidence.Sha256,
                        signed.Evidence.SignerThumbprint,
                        signed.TimestampAuthorityThumbprint,
                        signed.Evidence.TimestampedAt);
                })
                .ToList();

        return new ArtifactSigningReceiptV1(
            ready.Request.RequestId,
            ready.RequestDigest,
            ready.Request.ProjectId,
            ready.Request.ProfileId,
            ready.Request.ProfileVersion,
            ready.Request.SourceRepository,
            ready.Request.SourceCommit,
            ready.Request.ReleaseVersion,
            ready.Request.SignerPolicyId,
            ready.Request.TimestampPolicyId,
            ready.Submitter.SubjectPublicKeyInfoSha256,
            ready.Approver.SubjectPublicKeyInfoSha256,
            _receiptSigner.SubjectPublicKeyInfoSha256,
            unsigned,
            results,
            authenticode,
            _workerVersion,
            ready.SigningPolicy.SignToolSha256,
            signingAuditSequence,
            completedAt);
    }

    private static ReceiptArtifactV1 ReadReceiptArtifact(
        SigningProfileArtifactDefinition definition,
        string bundleDirectory)
    {
        using FileStream stream = WorkerDirectFile.OpenRead(
            Path.Combine(bundleDirectory, definition.FileName));
        if (stream.Length is <= 0 || stream.Length > definition.MaximumBytes)
        {
            throw new InvalidDataException(
                "Result artifact violates its compiled bound.");
        }

        return new ReceiptArtifactV1(
            definition.Role,
            definition.FileName,
            stream.Length,
            Convert.ToHexStringLower(SHA256.HashData(stream)));
    }

    private static bool TryCreateUnsignedSnapshot(
        ValidatedReadyRecord ready,
        string bundleDirectory,
        string unsignedDirectory)
    {
        if (Directory.Exists(unsignedDirectory)
            || File.Exists(unsignedDirectory))
        {
            return false;
        }

        Directory.CreateDirectory(unsignedDirectory);
        if (!IsDirectDirectory(unsignedDirectory))
        {
            return false;
        }

        foreach (SigningProfileArtifactDefinition definition
                 in ready.Profile.Descriptor.Artifacts)
        {
            string sourcePath =
                Path.Combine(bundleDirectory, definition.FileName);
            string destinationPath =
                Path.Combine(unsignedDirectory, definition.FileName);
            using FileStream source = WorkerDirectFile.OpenRead(sourcePath);
            using FileStream destination = new(
                destinationPath,
                new FileStreamOptions
                {
                    Mode = FileMode.CreateNew,
                    Access = FileAccess.Write,
                    Share = FileShare.None,
                    BufferSize = 64 * 1024,
                    Options = FileOptions.SequentialScan,
                });
            source.CopyTo(destination);
            destination.Flush(flushToDisk: true);
        }

        return ValidateBundleInventory(
            unsignedDirectory,
            ready.Profile.Descriptor);
    }

    private static bool TryCloseResultInventory(
        SigningProfileDescriptor descriptor,
        string workDirectory,
        string unsignedDirectory,
        string bundleDirectory)
    {
        if (!IsDirectDirectory(unsignedDirectory)
            || !IsDirectDirectory(bundleDirectory)
            || !ValidateBundleInventory(unsignedDirectory, descriptor))
        {
            return false;
        }

        foreach (SigningProfileArtifactDefinition definition
                 in descriptor.Artifacts)
        {
            File.Delete(Path.Combine(
                unsignedDirectory,
                definition.FileName));
        }

        Directory.Delete(unsignedDirectory, recursive: false);
        File.Delete(Path.Combine(workDirectory, RequestJsonFileName));
        File.Delete(Path.Combine(workDirectory, RequestSignatureFileName));
        File.Delete(Path.Combine(workDirectory, ApprovalSignatureFileName));
        foreach (SigningProfileArtifactDefinition definition
                 in descriptor.Artifacts.Where(definition =>
                     definition.Kind
                         is SigningProfileArtifactKind.JsonBuildEvidence))
        {
            File.Delete(Path.Combine(bundleDirectory, definition.FileName));
        }

        return true;
    }

    private static bool ValidateInitialInventoryRoot(string workDirectory)
    {
        if (!Path.IsPathFullyQualified(workDirectory)
            || !IsDirectDirectory(workDirectory))
        {
            return false;
        }

        HashSet<string> expected = new(StringComparer.Ordinal)
        {
            RequestJsonFileName,
            RequestSignatureFileName,
            ApprovalSignatureFileName,
            BundleDirectoryName,
        };
        return HasExactEntries(workDirectory, expected);
    }

    private static bool ValidateBundleInventory(
        string bundleDirectory,
        SigningProfileDescriptor descriptor)
    {
        if (!IsDirectDirectory(bundleDirectory))
        {
            return false;
        }

        HashSet<string> expected = descriptor.Artifacts
            .Select(definition => definition.FileName)
            .ToHashSet(StringComparer.Ordinal);
        if (!HasExactEntries(bundleDirectory, expected))
        {
            return false;
        }

        foreach (string fileName in expected)
        {
            try
            {
                using FileStream stream = WorkerDirectFile.OpenRead(
                    Path.Combine(bundleDirectory, fileName));
            }
            catch (Exception exception)
                when (exception is IOException
                    or UnauthorizedAccessException
                    or NotSupportedException)
            {
                return false;
            }
        }

        return true;
    }

    private static bool ValidateResultInventory(
        SigningProfileDescriptor descriptor,
        string workDirectory,
        string bundleDirectory,
        ArtifactSigningReceiptV1 receipt,
        ReadOnlySpan<byte> expectedReceiptJson,
        ReadOnlySpan<byte> expectedReceiptSignature)
    {
        HashSet<string> rootExpected = new(StringComparer.Ordinal)
        {
            ReceiptJsonFileName,
            ReceiptSignatureFileName,
            BundleDirectoryName,
        };
        HashSet<string> bundleExpected = descriptor.Artifacts
            .Where(definition =>
                definition.Kind
                    is not SigningProfileArtifactKind.JsonBuildEvidence)
            .Select(definition => definition.FileName)
            .ToHashSet(StringComparer.Ordinal);
        if (!IsDirectDirectory(workDirectory)
            || !IsDirectDirectory(bundleDirectory)
            || !HasExactEntries(workDirectory, rootExpected)
            || !HasExactEntries(bundleDirectory, bundleExpected))
        {
            return false;
        }

        try
        {
            byte[] actualReceiptJson = WorkerDirectFile.ReadBounded(
                Path.Combine(workDirectory, ReceiptJsonFileName),
                ArtifactSigningReceiptJsonSerializer
                    .MaximumReceiptJsonBytes);
            byte[] actualReceiptSignature = WorkerDirectFile.ReadBounded(
                Path.Combine(workDirectory, ReceiptSignatureFileName),
                DetachedCmsSignatureVerifier.MaximumSignatureBytes);
            if (!actualReceiptJson.AsSpan().SequenceEqual(
                    expectedReceiptJson)
                || !actualReceiptSignature.AsSpan().SequenceEqual(
                    expectedReceiptSignature))
            {
                return false;
            }

            Dictionary<(string Role, string File), ReceiptArtifactV1>
                receiptResults = receipt.ResultArtifacts.ToDictionary(
                    artifact => (artifact.Role, artifact.File),
                    artifact => artifact);
            foreach (SigningProfileArtifactDefinition definition
                     in descriptor.Artifacts.Where(definition =>
                         definition.Kind
                             is not SigningProfileArtifactKind
                                 .JsonBuildEvidence))
            {
                if (!receiptResults.TryGetValue(
                        (definition.Role, definition.FileName),
                        out ReceiptArtifactV1? expected))
                {
                    return false;
                }

                using FileStream stream = WorkerDirectFile.OpenRead(
                    Path.Combine(bundleDirectory, definition.FileName));
                if (stream.Length != expected.Size
                    || !string.Equals(
                        Convert.ToHexStringLower(
                            SHA256.HashData(stream)),
                        expected.Sha256,
                        StringComparison.Ordinal))
                {
                    return false;
                }
            }

            return true;
        }
        catch (Exception exception)
            when (exception is IOException
                or UnauthorizedAccessException
                or NotSupportedException)
        {
            return false;
        }
    }

    private static bool HasExactEntries(
        string directory,
        HashSet<string> expected)
    {
        try
        {
            string[] actual = Directory
                .EnumerateFileSystemEntries(directory)
                .Select(path => Path.GetFileName(path) ?? string.Empty)
                .ToArray();
            return actual.Length == expected.Count
                && actual.All(expected.Contains);
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

    private static bool IsDirectDirectory(string path)
    {
        try
        {
            FileAttributes attributes = File.GetAttributes(path);
            return attributes.HasFlag(FileAttributes.Directory)
                && !attributes.HasFlag(FileAttributes.ReparsePoint);
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

    private static bool TryWriteFileAtomically(
        string destinationPath,
        ReadOnlySpan<byte> content,
        bool overwrite)
    {
        if (content.IsEmpty || !Path.IsPathFullyQualified(destinationPath))
        {
            return false;
        }

        string temporaryPath = string.Concat(
            destinationPath,
            ".worker-new");
        if (File.Exists(temporaryPath))
        {
            return false;
        }

        try
        {
            using (FileStream stream = new(
                       temporaryPath,
                       new FileStreamOptions
                       {
                           Mode = FileMode.CreateNew,
                           Access = FileAccess.Write,
                           Share = FileShare.None,
                           BufferSize = 64 * 1024,
                           Options = FileOptions.SequentialScan,
                       }))
            {
                stream.Write(content);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, destinationPath, overwrite);
            return true;
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

    private static bool EvidenceMatchesPolicy(
        WorkerArtifactSigningResult result,
        SigningProfileArtifactDefinition definition,
        WorkerInstalledSigningPolicy policy)
    {
        VerifiedAuthenticodeArtifact evidence = result.Evidence!;
        return string.Equals(
                evidence.Role,
                definition.Role,
                StringComparison.Ordinal)
            && string.Equals(
                evidence.FileName,
                definition.FileName,
                StringComparison.Ordinal)
            && (policy.SignerThumbprint is null
                ? WorkerPolicyRules.IsUpperThumbprint(
                    evidence.SignerThumbprint)
                : string.Equals(
                    evidence.SignerThumbprint,
                    policy.SignerThumbprint,
                    StringComparison.Ordinal))
            && WorkerPolicyRules.IsUpperThumbprint(
                result.TimestampAuthorityThumbprint!);
    }

    private static SigningProfileArtifactDefinition GetManifestDefinition(
        SigningProfileDescriptor descriptor)
    {
        return descriptor.Artifacts.Single(definition =>
            definition.Kind is SigningProfileArtifactKind.JsonManifest);
    }

    private static bool FixedTimeDigestEquals(
        string left,
        string right)
    {
        return left.Length == right.Length
            && CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(left),
                Convert.FromHexString(right));
    }

    private static WorkerSigningOperationResult Failure(
        WorkerSigningFailure failure)
    {
        return WorkerSigningOperationResult.Failed(failure);
    }

    private static WorkerSigningFailure MapArtifactSigningFailure(
        WorkerArtifactSigningResult result)
    {
        return result.Error switch
        {
            WorkerArtifactSigningError.UnsignedInspectionFailed =>
                WorkerSigningFailure.ArtifactPrecheckFailed,
            WorkerArtifactSigningError.SignToolFailed =>
                WorkerSigningFailure.SignToolRejected,
            WorkerArtifactSigningError.SignedSnapshotInvalid
                or WorkerArtifactSigningError.SignedVerificationFailed =>
                WorkerSigningFailure.SignatureVerificationFailed,
            WorkerArtifactSigningError.None =>
                WorkerSigningFailure.SignatureVerificationFailed,
            _ => WorkerSigningFailure.SignatureVerificationFailed,
        };
    }

    private DateTimeOffset GetWholeSecondUtcNow()
    {
        DateTimeOffset now = _timeProvider.GetUtcNow().ToUniversalTime();
        return new DateTimeOffset(
            now.Year,
            now.Month,
            now.Day,
            now.Hour,
            now.Minute,
            now.Second,
            TimeSpan.Zero);
    }

    private static string GetWorkerVersion()
    {
        Version version = typeof(WorkerReadyRecordOperation)
            .Assembly
            .GetName()
            .Version
            ?? throw new InvalidOperationException(
                "Worker assembly version is unavailable.");
        return string.Create(
            CultureInfo.InvariantCulture,
            $"{version.Major}.{version.Minor}.{version.Build}");
    }

    private enum ReadyRecordError
    {
        None,
        InventoryInvalid,
        RequestInvalid,
        RequestExpired,
        ApprovalInvalid,
        AuthorizationInvalid,
        ProfileInvalid,
    }

    private sealed record ReadyRecordLoadResult(
        ValidatedReadyRecord? Record,
        ReadyRecordError Error)
    {
        internal bool IsSuccess =>
            Error is ReadyRecordError.None && Record is not null;

        internal static ReadyRecordLoadResult Success(
            ValidatedReadyRecord record)
        {
            return new ReadyRecordLoadResult(
                record,
                ReadyRecordError.None);
        }

        internal static ReadyRecordLoadResult Failure(
            ReadyRecordError error)
        {
            return new ReadyRecordLoadResult(null, error);
        }
    }

    private sealed record ValidatedReadyRecord(
        ArtifactSigningRequestV1 Request,
        string RequestDigest,
        ISigningProfile Profile,
        WorkerInstalledSigningPolicy SigningPolicy,
        CmsSignerIdentity Submitter,
        CmsSignerIdentity Approver);

    private sealed record AuthorizedSigners(
        CmsSignerIdentity Submitter,
        CmsSignerIdentity Approver);

    private sealed record SignedWorkerArtifact(
        VerifiedAuthenticodeArtifact Evidence,
        string TimestampAuthorityThumbprint);
}
