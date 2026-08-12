using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ArtifactSigning.Composition;
using ArtifactSigning.Profiles;
using ArtifactSigning.Protocol;

namespace ArtifactSigning.Cli;

internal static class CliApplication
{
    internal const int Success = 0;
    internal const int UsageError = 64;
    internal const int DataError = 65;
    internal const int NoInput = 66;
    internal const int ServiceUnavailable = 69;
    internal const int SoftwareError = 70;
    internal const int CannotCreate = 73;
    internal const int IoError = 74;
    internal const int TemporaryFailure = 75;
    internal const int PermissionDenied = 77;

    private const int MaximumReasonFileBytes = 4096;

    internal static Task<int> RunAsync(
        string[] args,
        TextWriter output,
        TextWriter error,
        TextReader input,
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(output);
        if (args is ["--version"])
        {
            return WriteVersionAsync(output);
        }

        return RunAsync(
            args,
            output,
            error,
            input,
            timeProvider,
            InstalledProfileSet.Create(),
            cancellationToken);
    }

    internal static async Task<int> RunAsync(
        string[] args,
        TextWriter output,
        TextWriter error,
        TextReader input,
        TimeProvider timeProvider,
        SigningProfilePackageSet profilePackages,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(profilePackages);
        CliProfileRegistry profiles = new(profilePackages);
        try
        {
            ParsedCommand command =
                ParsedCommand.Parse(args);
            if (command.Name is "--version")
            {
                if (command.ConfigurationPath is not null)
                {
                    throw new CliUsageException();
                }

                command.RequireNoOptions();
                command.RequireNoPositionals();
                return await WriteVersionAsync(output)
                    .ConfigureAwait(false);
            }

            if (command.Name is "verify")
            {
                CliConfiguration verifyConfiguration =
                    CliConfiguration.Load(
                        ResolveConfigurationPath(
                            command.ConfigurationPath));
                return await VerifyAsync(
                        command,
                        verifyConfiguration,
                        output,
                        timeProvider,
                        profiles)
                    .ConfigureAwait(false);
            }

            CliConfiguration configuration =
                CliConfiguration.Load(
                    ResolveConfigurationPath(
                        command.ConfigurationPath));
            using X509Certificate2 identity =
                CliCertificateLoader.LoadClientIdentity(
                    configuration.ClientIdentity,
                    WholeSecondNow(timeProvider));
            using SigningServiceClient client = new(
                configuration,
                identity);
            return command.Name switch
            {
                "profiles" => await ProfilesAsync(
                        command,
                        client,
                        output,
                        cancellationToken)
                    .ConfigureAwait(false),
                "submit" => await SubmitAsync(
                        command,
                        client,
                        identity,
                        output,
                        timeProvider,
                        profiles,
                        cancellationToken)
                    .ConfigureAwait(false),
                "status" => await StatusAsync(
                        command,
                        client,
                        output,
                        cancellationToken)
                    .ConfigureAwait(false),
                "review" => await ReviewAsync(
                        command,
                        client,
                        configuration,
                        output,
                        timeProvider,
                        cancellationToken)
                    .ConfigureAwait(false),
                "wait" => await WaitAsync(
                        command,
                        client,
                        output,
                        timeProvider,
                        cancellationToken)
                    .ConfigureAwait(false),
                "approve" or "reject" =>
                    await DecideAsync(
                            command,
                            client,
                            identity,
                            configuration,
                            output,
                            input,
                            timeProvider,
                            cancellationToken)
                        .ConfigureAwait(false),
                "cancel" => await CancelAsync(
                        command,
                        client,
                        output,
                        cancellationToken)
                    .ConfigureAwait(false),
                "download" => await DownloadAsync(
                        command,
                        client,
                        configuration,
                        output,
                        timeProvider,
                        profiles,
                        cancellationToken)
                    .ConfigureAwait(false),
                _ => throw new CliUsageException(),
            };
        }
        catch (CliUsageException)
        {
            await error.WriteLineAsync(
                    "artifact-signctl: usage error")
                .ConfigureAwait(false);
            return UsageError;
        }
        catch (CliServiceException exception)
        {
            await error.WriteLineAsync(string.Concat(
                    "artifact-signctl: ",
                    exception.Code))
                .ConfigureAwait(false);
            return exception.StatusCode switch
            {
                HttpStatusCode.Unauthorized
                    or HttpStatusCode.Forbidden =>
                    PermissionDenied,
                HttpStatusCode.NotFound => NoInput,
                HttpStatusCode.TooManyRequests
                    or HttpStatusCode
                        .ServiceUnavailable =>
                    TemporaryFailure,
                _ => DataError,
            };
        }
        catch (UnauthorizedAccessException)
        {
            await error.WriteLineAsync(
                    "artifact-signctl: permission denied")
                .ConfigureAwait(false);
            return PermissionDenied;
        }
        catch (FileNotFoundException)
        {
            await error.WriteLineAsync(
                    "artifact-signctl: input unavailable")
                .ConfigureAwait(false);
            return NoInput;
        }
        catch (InvalidDataException)
        {
            await error.WriteLineAsync(
                    "artifact-signctl: data verification failed")
                .ConfigureAwait(false);
            return DataError;
        }
        catch (CryptographicException)
        {
            await error.WriteLineAsync(
                    "artifact-signctl: identity verification failed")
                .ConfigureAwait(false);
            return PermissionDenied;
        }
        catch (HttpRequestException)
        {
            await error.WriteLineAsync(
                    "artifact-signctl: service unavailable")
                .ConfigureAwait(false);
            return ServiceUnavailable;
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            await error.WriteLineAsync(
                    "artifact-signctl: cancelled")
                .ConfigureAwait(false);
            return TemporaryFailure;
        }
        catch (IOException)
        {
            await error.WriteLineAsync(
                    "artifact-signctl: I/O failure")
                .ConfigureAwait(false);
            return IoError;
        }
        catch (CliCannotCreateException)
        {
            await error.WriteLineAsync(
                    "artifact-signctl: cannot create output")
                .ConfigureAwait(false);
            return CannotCreate;
        }
        catch (Exception exception)
            when (exception is not OutOfMemoryException)
        {
            await error.WriteLineAsync(
                    "artifact-signctl: software failure")
                .ConfigureAwait(false);
            return SoftwareError;
        }
    }

    private static async Task<int> WriteVersionAsync(
        TextWriter output)
    {
        Version version = typeof(CliApplication)
            .Assembly
            .GetName()
            .Version
            ?? throw new InvalidOperationException(
                "The CLI assembly version is unavailable.");
        await output.WriteLineAsync(
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"{version.Major}.{version.Minor}.{version.Build}"))
            .ConfigureAwait(false);
        return Success;
    }

    private static async Task<int> ProfilesAsync(
        ParsedCommand command,
        SigningServiceClient client,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        command.RequireNoOptions();
        if (command.Positionals.Count is not 1
            || command.Positionals[0] is not "list")
        {
            throw new CliUsageException();
        }

        IReadOnlyList<CliVisibleProfile> profiles =
            await client.GetProfilesAsync(cancellationToken)
                .ConfigureAwait(false);
        foreach (CliVisibleProfile profile in profiles)
        {
            await output.WriteLineAsync(string.Create(
                    CultureInfo.InvariantCulture,
                    $"{profile.ProjectId} {profile.ProfileId} {profile.ProfileVersion} {profile.MaximumRequestBytes} {profile.PackageId}@{profile.PackageVersion} {profile.PackageSha256} {profile.ProfileSetSha256}"))
                .ConfigureAwait(false);
        }

        return Success;
    }

    private static async Task<int> SubmitAsync(
        ParsedCommand command,
        SigningServiceClient client,
        X509Certificate2 identity,
        TextWriter output,
        TimeProvider timeProvider,
        CliProfileRegistry profiles,
        CancellationToken cancellationToken)
    {
        command.RequireNoPositionals();
        string project = command.TakeRequired("--project");
        string profile = command.TakeRequired("--profile");
        string bundle = command.TakeRequired("--bundle");
        string sourceRepository =
            command.TakeRequired("--source-repository");
        string sourceCommit =
            command.TakeRequired("--source-commit");
        string releaseVersion =
            command.TakeRequired("--release-version");
        command.RequireNoOptions();
        IReadOnlyList<CliVisibleProfile> visibleProfiles =
            await client.GetProfilesAsync(cancellationToken)
                .ConfigureAwait(false);
        profiles.RequireServerMatch(
            project,
            profile,
            visibleProfiles);
        using CliPreparedRequestArchive prepared =
            CliArchives.PrepareRequest(
                project,
                profile,
                bundle,
                sourceRepository,
                sourceCommit,
                releaseVersion,
                identity,
                timeProvider,
                profiles);
        using FileStream archive = File.OpenRead(
            prepared.ArchivePath);
        CliRequestAccepted accepted =
            await client.SubmitAsync(
                    archive,
                    archive.Length,
                    cancellationToken)
                .ConfigureAwait(false);
        if (accepted.RequestId !=
                prepared.Request.RequestId
            || !FixedDigestEquals(
                accepted.RequestDigest,
                prepared.RequestDigest)
            || !string.Equals(
                accepted.ProjectId,
                prepared.Request.ProjectId,
                StringComparison.Ordinal)
            || !string.Equals(
                accepted.ProfileId,
                prepared.Request.ProfileId,
                StringComparison.Ordinal)
            || accepted.ProfileVersion !=
                prepared.Request.ProfileVersion)
        {
            throw new InvalidDataException(
                "The signing service response is not bound to the request.");
        }

        await WriteRequestSummaryAsync(
                output,
                accepted.RequestId,
                accepted.RequestDigest,
                accepted.State)
            .ConfigureAwait(false);
        return Success;
    }

    private static async Task<int> StatusAsync(
        ParsedCommand command,
        SigningServiceClient client,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        command.RequireNoPositionals();
        Guid requestId = ParseRequestId(
            command.TakeRequired("--request"));
        command.RequireNoOptions();
        CliRequestStatus status =
            await client.GetStatusAsync(
                    requestId,
                    cancellationToken)
                .ConfigureAwait(false);
        await WriteStatusAsync(output, status)
            .ConfigureAwait(false);
        return Success;
    }

    private static async Task<int> ReviewAsync(
        ParsedCommand command,
        SigningServiceClient client,
        CliConfiguration configuration,
        TextWriter output,
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        command.RequireNoPositionals();
        Guid requestId = ParseRequestId(
            command.TakeRequired("--request"));
        string expectedDigest =
            command.TakeRequired("--expected-digest");
        if (!IsLowerSha256(expectedDigest))
        {
            throw new CliUsageException();
        }

        string format = command.TakeOptional("--format")
            ?? "text";
        if (format is not ("text" or "json"))
        {
            throw new CliUsageException();
        }

        command.RequireNoOptions();
        CliVerifiedReview verified =
            await GetVerifiedReviewAsync(
                    requestId,
                    expectedDigest,
                    client,
                    configuration,
                    timeProvider,
                    cancellationToken)
                .ConfigureAwait(false);
        if (format is "json")
        {
            await output.WriteLineAsync(
                    CliReviewSummaryJson.Serialize(
                        verified.Status,
                        verified.Review))
                .ConfigureAwait(false);
        }
        else
        {
            await WriteReviewSummaryAsync(
                    output,
                    verified.Review)
                .ConfigureAwait(false);
        }

        return Success;
    }

    private static async Task<int> WaitAsync(
        ParsedCommand command,
        SigningServiceClient client,
        TextWriter output,
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        command.RequireNoPositionals();
        Guid requestId = ParseRequestId(
            command.TakeRequired("--request"));
        int timeoutSeconds = command.TakeOptionalInt32(
            "--timeout-seconds",
            defaultValue: 900,
            minimum: 1,
            maximum: 1800);
        command.RequireNoOptions();
        DateTimeOffset deadline =
            timeProvider.GetUtcNow().AddSeconds(
                timeoutSeconds);
        while (true)
        {
            CliRequestStatus status =
                await client.GetStatusAsync(
                        requestId,
                        cancellationToken)
                    .ConfigureAwait(false);
            if (RequestStateTransitions.IsTerminal(
                    status.State))
            {
                await WriteStatusAsync(output, status)
                    .ConfigureAwait(false);
                return status.State is RequestState.Signed
                    ? Success
                    : DataError;
            }

            if (timeProvider.GetUtcNow() >= deadline)
            {
                return TemporaryFailure;
            }

            await Task.Delay(
                    TimeSpan.FromSeconds(2),
                    timeProvider,
                    cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private static async Task<int> DecideAsync(
        ParsedCommand command,
        SigningServiceClient client,
        X509Certificate2 identity,
        CliConfiguration configuration,
        TextWriter output,
        TextReader input,
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        command.RequireNoPositionals();
        Guid requestId = ParseRequestId(
            command.TakeRequired("--request"));
        string reasonPath =
            command.TakeRequired("--reason-file");
        string? expectedDigest =
            command.TakeOptional("--expected-digest");
        command.RequireNoOptions();
        if (expectedDigest is not null
            && !IsLowerSha256(expectedDigest))
        {
            throw new CliUsageException();
        }

        CliVerifiedReview verified =
            await GetVerifiedReviewAsync(
                    requestId,
                    expectedDigest,
                    client,
                    configuration,
                    timeProvider,
                    cancellationToken)
                .ConfigureAwait(false);
        CliReviewedRequest review = verified.Review;

        await WriteReviewSummaryAsync(output, review)
            .ConfigureAwait(false);
        ApprovalDecision decision =
            command.Name is "approve"
                ? ApprovalDecision.Approve
                : ApprovalDecision.Reject;
        if (expectedDigest is null)
        {
            string confirmation =
                decision is ApprovalDecision.Approve
                    ? "APPROVE"
                    : "REJECT";
            await output.WriteLineAsync(string.Concat(
                    "ConfirmationRequired=",
                    confirmation))
                .ConfigureAwait(false);
            string? entered = await input.ReadLineAsync(
                    cancellationToken)
                .ConfigureAwait(false);
            if (!string.Equals(
                    entered,
                    confirmation,
                    StringComparison.Ordinal))
            {
                return DataError;
            }
        }

        string reason = ReadReason(reasonPath);
        DateTimeOffset approvedAt =
            WholeSecondNow(timeProvider);
        ArtifactSigningApprovalV1 approval = new(
            requestId,
            review.RequestDigest,
            decision,
            reason,
            approvedAt,
            approvedAt.AddMinutes(5),
            CreateNonce());
        byte[] approvalJson =
            ArtifactSigningApprovalJsonSerializer
                .Serialize(approval);
        byte[] approvalCms =
            CliCertificateLoader.SignCms(
                approvalJson,
                identity,
                detached: false);
        CliDecisionAccepted accepted =
            await client.DecideAsync(
                    requestId,
                    approvalCms,
                    cancellationToken)
                .ConfigureAwait(false);
        if (accepted.RequestId != requestId
            || !FixedDigestEquals(
                accepted.RequestDigest,
                review.RequestDigest))
        {
            throw new InvalidDataException(
                "The signing decision response is invalid.");
        }

        await WriteRequestSummaryAsync(
                output,
                accepted.RequestId,
                accepted.RequestDigest,
                accepted.State)
            .ConfigureAwait(false);
        return Success;
    }

    private static async Task<CliVerifiedReview>
        GetVerifiedReviewAsync(
            Guid requestId,
            string? expectedDigest,
            SigningServiceClient client,
            CliConfiguration configuration,
            TimeProvider timeProvider,
            CancellationToken cancellationToken)
    {
        CliRequestStatus status =
            await client.GetStatusAsync(
                    requestId,
                    cancellationToken)
                .ConfigureAwait(false);
        if (!status.CanApprove
            || status.State is not
                RequestState.PendingApproval)
        {
            throw new InvalidDataException(
                "The signing request cannot be approved.");
        }

        byte[] reviewArchive =
            await client.GetReviewAsync(
                    requestId,
                    cancellationToken)
                .ConfigureAwait(false);
        CmsTrustPolicy submitterTrust =
            CliCertificateLoader.CreateTrustPolicy(
                configuration.SubmitterTrust);
        DateTimeOffset reviewTime =
            WholeSecondNow(timeProvider);
        CliReviewedRequest review =
            CliArchives.ReadAndVerifyReview(
                reviewArchive,
                submitterTrust,
                reviewTime);
        ValidateReviewBinding(
            status,
            review,
            reviewTime);
        if (expectedDigest is not null
            && !FixedDigestEquals(
                expectedDigest,
                review.RequestDigest))
        {
            throw new InvalidDataException(
                "The independently reviewed digest does not match.");
        }

        return new CliVerifiedReview(status, review);
    }

    private static async Task<int> CancelAsync(
        ParsedCommand command,
        SigningServiceClient client,
        TextWriter output,
        CancellationToken cancellationToken)
    {
        command.RequireNoPositionals();
        Guid requestId = ParseRequestId(
            command.TakeRequired("--request"));
        command.RequireNoOptions();
        CliDecisionAccepted accepted =
            await client.CancelAsync(
                    requestId,
                    cancellationToken)
                .ConfigureAwait(false);
        await WriteRequestSummaryAsync(
                output,
                accepted.RequestId,
                accepted.RequestDigest,
                accepted.State)
            .ConfigureAwait(false);
        return Success;
    }

    private static async Task<int> DownloadAsync(
        ParsedCommand command,
        SigningServiceClient client,
        CliConfiguration configuration,
        TextWriter output,
        TimeProvider timeProvider,
        CliProfileRegistry profiles,
        CancellationToken cancellationToken)
    {
        command.RequireNoPositionals();
        Guid requestId = ParseRequestId(
            command.TakeRequired("--request"));
        string outputPath = Path.GetFullPath(
            command.TakeRequired("--output"));
        command.RequireNoOptions();
        CliRequestStatus status =
            await client.GetStatusAsync(
                    requestId,
                    cancellationToken)
                .ConfigureAwait(false);
        if (status.State is not RequestState.Signed
            || !status.CanDownload)
        {
            throw new InvalidDataException(
                "The signed result is not available.");
        }

        string? parent = Path.GetDirectoryName(
            outputPath);
        if (string.IsNullOrEmpty(parent)
            || !Directory.Exists(parent)
            || File.Exists(outputPath)
            || Directory.Exists(outputPath))
        {
            throw new CliCannotCreateException();
        }

        string temporaryPath = Path.Combine(
            parent,
            $".artifact-signctl-{Guid.NewGuid():N}.tmp");
        try
        {
            using (FileStream destination =
                   CliFileSecurity.CreateOwnerOnlyFile(
                       temporaryPath))
            {
                await client.DownloadAsync(
                        requestId,
                        destination,
                        cancellationToken)
                    .ConfigureAwait(false);
                await destination.FlushAsync(
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            CmsTrustPolicy receiptTrust =
                CliCertificateLoader.CreateTrustPolicy(
                    configuration.ReceiptTrust);
            CliVerifiedResult verified =
                CliResultVerifier.Verify(
                    temporaryPath,
                    receiptTrust,
                    WholeSecondNow(timeProvider),
                    profiles,
                    requestId,
                    status.RequestDigest);
            try
            {
                File.Move(
                    temporaryPath,
                    outputPath,
                    overwrite: false);
            }
            catch (IOException exception)
            {
                throw new CliCannotCreateException(
                    exception);
            }
            await output.WriteLineAsync(string.Create(
                    CultureInfo.InvariantCulture,
                    $"RequestId={verified.RequestId:D} RequestDigest={verified.RequestDigest} ReceiptDigest={verified.ReceiptDigest} State=Signed"))
                .ConfigureAwait(false);
            return Success;
        }
        finally
        {
            TryDeleteFile(temporaryPath);
        }
    }

    private static Task<int> VerifyAsync(
        ParsedCommand command,
        CliConfiguration configuration,
        TextWriter output,
        TimeProvider timeProvider,
        CliProfileRegistry profiles)
    {
        command.RequireNoPositionals();
        string resultPath = Path.GetFullPath(
            command.TakeRequired("--result"));
        command.RequireNoOptions();
        CmsTrustPolicy receiptTrust =
            CliCertificateLoader.CreateTrustPolicy(
                configuration.ReceiptTrust);
        CliVerifiedResult verified =
            CliResultVerifier.Verify(
                resultPath,
                receiptTrust,
                WholeSecondNow(timeProvider),
                profiles);
        return WriteVerifiedAsync(output, verified);
    }

    private static async Task<int> WriteVerifiedAsync(
        TextWriter output,
        CliVerifiedResult verified)
    {
        await output.WriteLineAsync(string.Create(
                CultureInfo.InvariantCulture,
                $"RequestId={verified.RequestId:D} RequestDigest={verified.RequestDigest} ReceiptDigest={verified.ReceiptDigest} Profile={verified.ProfileId}/{verified.ProfileVersion} SourceCommit={verified.SourceCommit} ReleaseVersion={verified.ReleaseVersion} CompletedAt={FormatTimestamp(verified.CompletedAt)}"))
            .ConfigureAwait(false);
        return Success;
    }

    private static void ValidateReviewBinding(
        CliRequestStatus status,
        CliReviewedRequest review,
        DateTimeOffset reviewTime)
    {
        ArtifactSigningRequestV1 request =
            review.Request;
        if (request.RequestId != status.RequestId
            || !FixedDigestEquals(
                review.RequestDigest,
                status.RequestDigest)
            || !string.Equals(
                request.ProjectId,
                status.ProjectId,
                StringComparison.Ordinal)
            || !string.Equals(
                request.ProfileId,
                status.ProfileId,
                StringComparison.Ordinal)
            || request.ProfileVersion !=
                status.ProfileVersion
            || !string.Equals(
                request.SourceRepository,
                status.SourceRepository,
                StringComparison.Ordinal)
            || !string.Equals(
                request.SourceCommit,
                status.SourceCommit,
                StringComparison.Ordinal)
            || !string.Equals(
                request.ReleaseVersion,
                status.ReleaseVersion,
                StringComparison.Ordinal)
            || request.RequestedAt > reviewTime
            || request.ExpiresAt <= reviewTime)
        {
            throw new InvalidDataException(
                "The signed review does not match status.");
        }
    }

    private static string ReadReason(string path)
    {
        string fullPath = Path.GetFullPath(path);
        CliFileSecurity.RequireOwnerOnlyFile(
            fullPath,
            MaximumReasonFileBytes);
        byte[] bytes = CliFileSecurity.ReadBounded(
            fullPath,
            MaximumReasonFileBytes);
        return new UTF8Encoding(
                encoderShouldEmitUTF8Identifier: false,
                throwOnInvalidBytes: true)
            .GetString(bytes)
            .TrimEnd('\r', '\n');
    }

    private static async Task WriteStatusAsync(
        TextWriter output,
        CliRequestStatus status)
    {
        await output.WriteLineAsync(string.Create(
                CultureInfo.InvariantCulture,
                $"RequestId={status.RequestId:D} RequestDigest={status.RequestDigest} State={status.State} ResultCode={status.ResultCode} Profile={status.ProfileId}/{status.ProfileVersion} UpdatedAt={FormatTimestamp(status.UpdatedAt)} CanApprove={status.CanApprove.ToString(CultureInfo.InvariantCulture)} CanDownload={status.CanDownload.ToString(CultureInfo.InvariantCulture)}"))
            .ConfigureAwait(false);
    }

    private static async Task WriteReviewSummaryAsync(
        TextWriter output,
        CliReviewedRequest review)
    {
        ArtifactSigningRequestV1 request =
            review.Request;
        await output.WriteLineAsync(string.Create(
                CultureInfo.InvariantCulture,
                $"RequestId={request.RequestId:D} RequestDigest={review.RequestDigest} Project={request.ProjectId} Profile={request.ProfileId}/{request.ProfileVersion} SourceCommit={request.SourceCommit} ReleaseVersion={request.ReleaseVersion} ExpiresAt={FormatTimestamp(request.ExpiresAt)} SubmitterSpkiSha256={review.Submitter.SubjectPublicKeyInfoSha256}"))
            .ConfigureAwait(false);
        foreach (RequestArtifactV1 artifact
                 in request.Artifacts)
        {
            await output.WriteLineAsync(string.Create(
                    CultureInfo.InvariantCulture,
                    $"Artifact={artifact.Role}/{artifact.File} Size={artifact.Size} Sha256={artifact.Sha256}"))
                .ConfigureAwait(false);
        }
    }

    private static Task WriteRequestSummaryAsync(
        TextWriter output,
        Guid requestId,
        string requestDigest,
        RequestState state)
    {
        return output.WriteLineAsync(string.Create(
            CultureInfo.InvariantCulture,
            $"RequestId={requestId:D} RequestDigest={requestDigest} State={state}"));
    }

    private static Guid ParseRequestId(string value)
    {
        if (!Guid.TryParseExact(
                value,
                "D",
                out Guid requestId)
            || requestId == Guid.Empty
            || !string.Equals(
                requestId.ToString("D"),
                value,
                StringComparison.Ordinal))
        {
            throw new CliUsageException();
        }

        return requestId;
    }

    private static string ResolveConfigurationPath(
        string? explicitPath)
    {
        if (!string.IsNullOrEmpty(explicitPath))
        {
            return Path.GetFullPath(explicitPath);
        }

        string? environmentPath =
            Environment.GetEnvironmentVariable(
                "ARTIFACT_SIGNING_CONFIG");
        if (!string.IsNullOrWhiteSpace(environmentPath))
        {
            return Path.GetFullPath(environmentPath);
        }

        string configurationRoot =
            Environment.GetFolderPath(
                Environment.SpecialFolder
                    .ApplicationData);
        if (string.IsNullOrEmpty(configurationRoot))
        {
            throw new CliUsageException();
        }

        return Path.Combine(
            configurationRoot,
            "artifact-signing",
            "client.json");
    }

    private static string CreateNonce()
    {
        return Convert.ToBase64String(
                RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
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

    private static string FormatTimestamp(
        DateTimeOffset value)
    {
        return value.ToString(
            "yyyy-MM-dd'T'HH:mm:ss'Z'",
            CultureInfo.InvariantCulture);
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
            // Owner-private incomplete output is best-effort cleanup.
        }
        catch (UnauthorizedAccessException)
        {
            // Owner-private incomplete output is best-effort cleanup.
        }
    }

    private sealed class CliUsageException : Exception;

    private sealed class CliCannotCreateException :
        Exception
    {
        internal CliCannotCreateException()
        {
        }

        internal CliCannotCreateException(
            Exception innerException)
            : base(
                "The output cannot be created.",
                innerException)
        {
        }
    }

    private sealed record CliVerifiedReview(
        CliRequestStatus Status,
        CliReviewedRequest Review);

    private sealed class ParsedCommand
    {
        private readonly Dictionary<string, string> _options;

        private ParsedCommand(
            string name,
            string? configurationPath,
            IReadOnlyList<string> positionals,
            Dictionary<string, string> options)
        {
            Name = name;
            ConfigurationPath = configurationPath;
            Positionals = positionals;
            _options = options;
        }

        internal string Name { get; }

        internal string? ConfigurationPath { get; }

        internal IReadOnlyList<string> Positionals
        {
            get;
        }

        internal static ParsedCommand Parse(
            string[] args)
        {
            if (args.Length is 0)
            {
                throw new CliUsageException();
            }

            string name = args[0];
            string? configurationPath = null;
            List<string> positionals = [];
            Dictionary<string, string> options =
                new(StringComparer.Ordinal);
            for (int index = 1; index < args.Length;)
            {
                string token = args[index];
                if (!token.StartsWith(
                        "--",
                        StringComparison.Ordinal))
                {
                    positionals.Add(token);
                    index++;
                    continue;
                }

                if (index + 1 >= args.Length
                    || args[index + 1].StartsWith(
                        "--",
                        StringComparison.Ordinal))
                {
                    throw new CliUsageException();
                }

                string value = args[index + 1];
                if (token is "--config")
                {
                    if (configurationPath is not null)
                    {
                        throw new CliUsageException();
                    }

                    configurationPath = value;
                }
                else if (!options.TryAdd(token, value))
                {
                    throw new CliUsageException();
                }

                index += 2;
            }

            return new ParsedCommand(
                name,
                configurationPath,
                positionals.AsReadOnly(),
                options);
        }

        internal string TakeRequired(string name)
        {
            return TakeOptional(name)
                ?? throw new CliUsageException();
        }

        internal string? TakeOptional(string name)
        {
            if (!_options.Remove(
                    name,
                    out string? value))
            {
                return null;
            }

            if (string.IsNullOrEmpty(value)
                || value.Length > 4096)
            {
                throw new CliUsageException();
            }

            return value;
        }

        internal int TakeOptionalInt32(
            string name,
            int defaultValue,
            int minimum,
            int maximum)
        {
            string? value = TakeOptional(name);
            if (value is null)
            {
                return defaultValue;
            }

            if (!int.TryParse(
                    value,
                    NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out int parsed)
                || parsed < minimum
                || parsed > maximum)
            {
                throw new CliUsageException();
            }

            return parsed;
        }

        internal void RequireNoOptions()
        {
            if (_options.Count is not 0)
            {
                throw new CliUsageException();
            }
        }

        internal void RequireNoPositionals()
        {
            if (Positionals.Count is not 0)
            {
                throw new CliUsageException();
            }
        }
    }
}
