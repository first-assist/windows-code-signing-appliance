using System.Formats.Tar;
using System.Globalization;
using System.Net.Mime;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using ArtifactSigning.Profiles;
using ArtifactSigning.Protocol;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace ArtifactSigning.Gateway;

public sealed record GatewayApiRuntime(
    GatewayStateStore StateStore,
    GatewayAuthorizationRegistry Authorization,
    SigningProfileRegistry Profiles,
    GatewaySubmissionProcessor SubmissionProcessor,
    GatewayApprovalProcessor ApprovalProcessor,
    IGatewayWorkerNotifier WorkerNotifier,
    GatewayResultProcessor ResultProcessor,
    TimeProvider TimeProvider,
    GatewayAuditAnchorReader? AuditAnchorReader = null,
    GatewayReadinessProbe? ReadinessProbe = null);

public static class GatewayApiApplication
{
    public const string RequestContentType =
        "application/vnd.artifact-signing.request.v1+tar";
    public const string ApprovalContentType =
        "application/vnd.artifact-signing.approval.v1+pkcs7";
    public const string ReviewContentType =
        "application/vnd.artifact-signing.review.v1+tar";
    public const string ResultContentType =
        "application/vnd.artifact-signing.result.v1+tar";
    public const long MaximumRequestBodyBytes =
        100L * 1024 * 1024;
    public const int MaximumApprovalBodyBytes =
        DetachedCmsSignatureVerifier.MaximumSignatureBytes;

    private const string MutationPolicyName =
        "GatewayMutations";
    private static readonly object IdentityKey = new();

    public static void AddGatewayApiServices(
        IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.Configure<JsonOptions>(options =>
        {
            options.SerializerOptions.PropertyNamingPolicy = null;
            options.SerializerOptions.DictionaryKeyPolicy = null;
            options.SerializerOptions.Converters.Add(
                new JsonStringEnumConverter());
        });
        services.AddProblemDetails();
        services.AddRequestTimeouts(options =>
        {
            options.DefaultPolicy = new Microsoft.AspNetCore
                .Http.Timeouts.RequestTimeoutPolicy
            {
                Timeout = TimeSpan.FromSeconds(120),
                TimeoutStatusCode =
                    StatusCodes.Status503ServiceUnavailable,
            };
        });
        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode =
                StatusCodes.Status429TooManyRequests;
            options.OnRejected = async (context, token) =>
            {
                context.HttpContext.Response.ContentType =
                    MediaTypeNames.Application.Json;
                await context.HttpContext.Response
                    .WriteAsJsonAsync(
                        new GatewayProblem(
                            "RequestLimitReached",
                            "The signing service is busy."),
                        cancellationToken: token)
                    .ConfigureAwait(false);
            };
            options.AddConcurrencyLimiter(
                MutationPolicyName,
                limiter =>
                {
                    limiter.PermitLimit = 1;
                    limiter.QueueLimit = 0;
                    limiter.QueueProcessingOrder =
                        QueueProcessingOrder.OldestFirst;
                });
        });
    }

    public static void Configure(
        WebApplication application,
        GatewayApiRuntime runtime)
    {
        ArgumentNullException.ThrowIfNull(application);
        ArgumentNullException.ThrowIfNull(runtime);

        application.UseExceptionHandler(handler =>
        {
            handler.Run(context =>
            {
                context.Response.StatusCode =
                    StatusCodes.Status503ServiceUnavailable;
                context.Response.ContentType =
                    MediaTypeNames.Application.Json;
                return context.Response.WriteAsJsonAsync(
                    new GatewayProblem(
                        "SigningUnavailable",
                        "The signing service is unavailable."),
                    cancellationToken:
                        context.RequestAborted);
            });
        });
        application.Use(async (context, next) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers.Pragma = "no-cache";
            await next(context).ConfigureAwait(false);
        });
        application.UseRequestTimeouts();
        application.UseRateLimiter();
        application.Use(async (context, next) =>
        {
            X509Certificate2? certificate =
                await context.Connection
                    .GetClientCertificateAsync(
                        context.RequestAborted)
                    .ConfigureAwait(false);
            if (certificate is null)
            {
                await WriteProblemAsync(
                        context,
                        StatusCodes.Status401Unauthorized,
                        "AuthenticationRequired",
                        "A client certificate is required.")
                    .ConfigureAwait(false);
                return;
            }

            GatewayClientIdentity identity = new(
                CertificateIdentity.ComputeCertificateSha256(
                    certificate),
                CertificateIdentity
                    .ComputeSubjectPublicKeyInfoSha256(
                        certificate));
            if (!runtime.Authorization.IsAllowedClient(identity))
            {
                await WriteProblemAsync(
                        context,
                        StatusCodes.Status403Forbidden,
                        "ClientNotAuthorized",
                        "The client is not authorized.")
                    .ConfigureAwait(false);
                return;
            }

            DateTimeOffset observedAt = WholeSecondNow(
                runtime.TimeProvider);
            GatewayIdentityObservationResult observation =
                runtime.StateStore.ObserveClientIdentity(
                    identity.CertificateSha256,
                    identity.SubjectPublicKeyInfoSha256,
                    observedAt);
            if (observation.Outcome
                is GatewayIdentityObservationOutcome
                    .IdentityMismatch)
            {
                await WriteProblemAsync(
                        context,
                        StatusCodes.Status403Forbidden,
                        "ClientNotAuthorized",
                        "The client is not authorized.")
                    .ConfigureAwait(false);
                return;
            }

            context.Items[IdentityKey] = identity;
            await next(context).ConfigureAwait(false);
        });

        application.MapGet(
            "/v1/health/live",
            static () => Results.Json(
                new GatewayHealthResponse("Live")));
        application.MapGet(
            "/v1/health/ready",
            () =>
            {
                return runtime.ReadinessProbe?.IsReady()
                        is true
                    ? Results.Json(
                        new GatewayHealthResponse("Ready"))
                    : Results.Json(
                        new GatewayHealthResponse("NotReady"),
                        statusCode: StatusCodes
                            .Status503ServiceUnavailable);
            });
        application.MapGet(
            "/v1/audit/head",
            (HttpContext context) =>
                AuditHead(context, runtime));
        application.MapGet(
            "/v1/profiles",
            (HttpContext context) => Results.Json(
                new GatewayProfilesResponse(
                    GatewayProfilesResponse.FormatIdentifier,
                    runtime.Authorization.GetVisibleProfiles(
                        GetIdentity(context)))));
        application.MapPost(
                "/v1/requests",
                async (HttpContext context) =>
                {
                    IResult result = await SubmitAsync(
                            context,
                            runtime)
                        .ConfigureAwait(false);
                    await result.ExecuteAsync(context)
                        .ConfigureAwait(false);
                })
            .RequireRateLimiting(MutationPolicyName);
        application.MapGet(
            "/v1/requests/{requestId}/review",
            (HttpContext context, string requestId) =>
                Review(context, requestId, runtime));
        application.MapGet(
            "/v1/requests/{requestId}",
            (HttpContext context, string requestId) =>
                Status(context, requestId, runtime));
        application.MapPost(
                "/v1/requests/{requestId}/approvals",
                async (
                    HttpContext context,
                    string requestId) =>
                {
                    IResult result = await ApproveAsync(
                            context,
                            requestId,
                            runtime)
                        .ConfigureAwait(false);
                    await result.ExecuteAsync(context)
                        .ConfigureAwait(false);
                })
            .RequireRateLimiting(MutationPolicyName);
        application.MapPost(
                "/v1/requests/{requestId}/cancel",
                (HttpContext context, string requestId) =>
                    Cancel(context, requestId, runtime))
            .RequireRateLimiting(MutationPolicyName);
        application.MapGet(
            "/v1/requests/{requestId}/bundle",
            (HttpContext context, string requestId) =>
                Bundle(context, requestId, runtime));
    }

    private static async Task<IResult> SubmitAsync(
        HttpContext context,
        GatewayApiRuntime runtime)
    {
        if (!HasExactContentType(
                context.Request,
                RequestContentType))
        {
            return Problem(
                StatusCodes.Status415UnsupportedMediaType,
                "ArchiveInvalid",
                "The request archive is invalid.");
        }

        GatewayClientIdentity identity = GetIdentity(context);
        GatewayInstalledAuthorizationPolicy? authorization =
            runtime.Authorization.ResolveSubmitter(identity);
        if (authorization is null)
        {
            return Problem(
                StatusCodes.Status403Forbidden,
                "ClientNotAuthorized",
                "The client is not authorized.");
        }

        string transportDirectory =
            runtime.StateStore.Layout
                .CreateReceivingDirectoryPath();
        GatewaySubmissionResult result;
        try
        {
            Directory.CreateDirectory(transportDirectory);
            string transportArchive = Path.Combine(
                transportDirectory,
                "request.tar");
            bool copied = await CopyRequestBodyAsync(
                    context.Request.Body,
                    transportArchive,
                    MaximumRequestBodyBytes,
                    context.RequestAborted)
                .ConfigureAwait(false);
            if (!copied)
            {
                return Problem(
                    StatusCodes.Status400BadRequest,
                    "ArchiveInvalid",
                    "The request archive is invalid.");
            }

            using FileStream archive =
                GatewayDirectFile.OpenRead(transportArchive);
            result = runtime.SubmissionProcessor.Process(
                archive,
                authorization.SubmitterPolicy,
                identity.SubjectPublicKeyInfoSha256);
        }
        finally
        {
            TryDeleteOwnedDirectory(transportDirectory);
        }
        if (!result.IsSuccess)
        {
            return SubmissionProblem(result.Error);
        }

        GatewayRequestRecord request = result.Request!;
        return Results.Json(
            new GatewayRequestAcceptedResponse(
                request.RequestId,
                request.RequestDigest,
                request.State,
                request.ProjectId,
                request.ProfileId,
                request.ProfileVersion,
                request.ExpiresAt),
            statusCode: StatusCodes.Status202Accepted);
    }

    private static IResult Review(
        HttpContext context,
        string requestIdText,
        GatewayApiRuntime runtime)
    {
        if (!TryParseRequestId(
                requestIdText,
                out Guid requestId))
        {
            return NotFound();
        }

        GatewayRequestRecord? request =
            runtime.StateStore.GetRequest(requestId);
        if (request is null)
        {
            return NotFound();
        }

        if (!runtime.Authorization.CanReadReview(
                GetIdentity(context),
                request))
        {
            return Forbidden();
        }

        string directory =
            runtime.StateStore.Layout
                .GetPendingRequestDirectory(requestId);
        if (!Directory.Exists(directory))
        {
            directory = runtime.StateStore.Layout
                .GetReadyRequestDirectory(requestId);
        }

        return Directory.Exists(directory)
            ? new GatewayReviewTarResult(directory)
            : Problem(
                StatusCodes.Status409Conflict,
                "SigningUnavailable",
                "The requested review is unavailable.");
    }

    private static IResult Status(
        HttpContext context,
        string requestIdText,
        GatewayApiRuntime runtime)
    {
        if (!TryParseRequestId(
                requestIdText,
                out Guid requestId))
        {
            return NotFound();
        }

        GatewayRequestRecord? request =
            runtime.StateStore.GetRequest(requestId);
        if (request is null)
        {
            return NotFound();
        }

        GatewayClientIdentity identity = GetIdentity(context);
        if (!runtime.Authorization.CanReadStatus(
                identity,
                request))
        {
            return Forbidden();
        }

        request = ObserveWorkerResult(
            runtime,
            request);
        bool canApprove =
            request.State is RequestState.PendingApproval
            && runtime.Authorization.ResolveApprover(
                identity,
                request) is not null;
        bool canDownload =
            request.State is RequestState.Signed
            && runtime.Authorization.CanDownload(
                identity,
                request);
        return Results.Json(new GatewayStatusResponse(
            request.RequestId,
            request.RequestDigest,
            request.State,
            request.ResultCode,
            request.ProjectId,
            request.ProfileId,
            request.ProfileVersion,
            request.SourceRepository,
            request.SourceCommit,
            request.ReleaseVersion,
            request.RequestedAt,
            request.ExpiresAt,
            request.CreatedAt,
            request.UpdatedAt,
            canApprove,
            canDownload));
    }

    private static IResult AuditHead(
        HttpContext context,
        GatewayApiRuntime runtime)
    {
        if (!runtime.Authorization.CanReadAuditHead(
                GetIdentity(context)))
        {
            return Forbidden();
        }

        if (runtime.AuditAnchorReader is null)
        {
            return Problem(
                StatusCodes.Status503ServiceUnavailable,
                "SigningUnavailable",
                "The signing service is unavailable.");
        }

        try
        {
            AuditHeadV1 gateway =
                runtime.StateStore.GetAuditHead();
            GatewayVerifiedWorkerAuditAnchor worker =
                runtime.AuditAnchorReader.ReadCurrent(
                    WholeSecondNow(runtime.TimeProvider));
            return Results.Json(
                new GatewayAuditHeadResponse(
                    "ArtifactSigningAuditHeadV1",
                    gateway.Sequence,
                    gateway.EventDigest,
                    worker.Anchor.WorkerSequence,
                    worker.Anchor.WorkerEventDigest,
                    worker.Anchor.WorkerVersion,
                    worker.Anchor.WorkerReady,
                    worker.Anchor
                        .TimestampDependencyReady,
                    worker.Anchor.PublishedAt,
                    worker.Anchor.ExpiresAt,
                    worker.Anchor
                        .ReceiptSignerSpkiSha256,
                    Convert.ToBase64String(
                        worker.AnchorJson.Span),
                    Convert.ToBase64String(
                        worker.AnchorSignature.Span)));
        }
        catch (Exception exception)
            when (exception is not OutOfMemoryException)
        {
            return Problem(
                StatusCodes.Status503ServiceUnavailable,
                "SigningUnavailable",
                "The signing service is unavailable.");
        }
    }

    private static async Task<IResult> ApproveAsync(
        HttpContext context,
        string requestIdText,
        GatewayApiRuntime runtime)
    {
        if (!TryParseRequestId(
                requestIdText,
                out Guid requestId))
        {
            return NotFound();
        }

        if (!HasExactContentType(
                context.Request,
                ApprovalContentType))
        {
            return Problem(
                StatusCodes.Status415UnsupportedMediaType,
                "ApprovalInvalid",
                "The approval is invalid.");
        }

        GatewayRequestRecord? current =
            runtime.StateStore.GetRequest(requestId);
        if (current is null)
        {
            return NotFound();
        }

        GatewayClientIdentity identity = GetIdentity(context);
        GatewayInstalledAuthorizationPolicy? authorization =
            runtime.Authorization.ResolveApprover(
                identity,
                current);
        if (authorization is null)
        {
            return Forbidden();
        }

        byte[]? body = await ReadBoundedBodyAsync(
                context.Request.Body,
                MaximumApprovalBodyBytes,
                context.RequestAborted)
            .ConfigureAwait(false);
        if (body is null)
        {
            return Problem(
                StatusCodes.Status400BadRequest,
                "ApprovalInvalid",
                "The approval is invalid.");
        }

        GatewayApprovalResult result =
            runtime.ApprovalProcessor.Process(
                requestId,
                body,
                authorization.ApproverPolicy,
                identity.SubjectPublicKeyInfoSha256);
        if (!result.IsSuccess)
        {
            return ApprovalProblem(result.Error);
        }

        GatewayRequestRecord accepted = result.Request!;
        if (result.WorkerNotificationRequired)
        {
            GatewayWorkerNotificationResult notification =
                await runtime.WorkerNotifier.NotifyAsync(
                        requestId,
                        context.RequestAborted)
                    .ConfigureAwait(false);
            if (!notification.IsSuccess)
            {
                return Problem(
                    StatusCodes.Status503ServiceUnavailable,
                    "SigningUnavailable",
                    "The signing worker is unavailable.");
            }

            GatewayRequestRecord approved = accepted;
            GatewayMutationResult dispatch =
                runtime.StateStore.TryMarkWorkerDispatched(
                    approved.RequestId,
                    approved.RequestDigest,
                    approved.RowVersion,
                    WholeSecondNow(runtime.TimeProvider));
            if (dispatch.Outcome is not (
                    GatewayMutationOutcome.Applied
                    or GatewayMutationOutcome.AlreadyApplied))
            {
                return Problem(
                    StatusCodes.Status503ServiceUnavailable,
                    "SigningUnavailable",
                    "The signing worker is unavailable.");
            }

            if (dispatch.Request is not null)
            {
                accepted = dispatch.Request;
            }
        }

        return Results.Json(
            new GatewayDecisionAcceptedResponse(
                accepted.RequestId,
                accepted.RequestDigest,
                accepted.State),
            statusCode: StatusCodes.Status202Accepted);
    }

    private static IResult Cancel(
        HttpContext context,
        string requestIdText,
        GatewayApiRuntime runtime)
    {
        if (!TryParseRequestId(
                requestIdText,
                out Guid requestId))
        {
            return NotFound();
        }

        GatewayRequestRecord? current =
            runtime.StateStore.GetRequest(requestId);
        if (current is null)
        {
            return NotFound();
        }

        if (!runtime.Authorization.IsOriginalSubmitter(
                GetIdentity(context),
                current))
        {
            return Forbidden();
        }

        GatewayMutationResult result =
            runtime.StateStore.TryCancel(
                requestId,
                current.RequestDigest,
                current.RowVersion,
                WholeSecondNow(runtime.TimeProvider));
        if (result.Outcome is not (
                GatewayMutationOutcome.Applied
                or GatewayMutationOutcome.AlreadyApplied)
            || result.Request is null)
        {
            return Problem(
                StatusCodes.Status409Conflict,
                "RequestConflict",
                "The request cannot be cancelled.");
        }

        TryDeleteUnexecutedRequest(
            runtime.StateStore.Layout,
            requestId);
        return Results.Json(
            new GatewayDecisionAcceptedResponse(
                result.Request.RequestId,
                result.Request.RequestDigest,
                result.Request.State),
            statusCode: StatusCodes.Status202Accepted);
    }

    private static IResult Bundle(
        HttpContext context,
        string requestIdText,
        GatewayApiRuntime runtime)
    {
        if (!TryParseRequestId(
                requestIdText,
                out Guid requestId))
        {
            return NotFound();
        }

        GatewayRequestRecord? request =
            runtime.StateStore.GetRequest(requestId);
        if (request is null)
        {
            return NotFound();
        }

        if (!runtime.Authorization.CanDownload(
                GetIdentity(context),
                request))
        {
            return Forbidden();
        }

        request = ObserveWorkerResult(
            runtime,
            request);
        return request.State is RequestState.Signed
            ? new GatewayBundleTarResult(
                runtime.ResultProcessor,
                request)
            : Problem(
                StatusCodes.Status409Conflict,
                "RequestConflict",
                "The signed result is not ready.");
    }

    private static GatewayRequestRecord ObserveWorkerResult(
        GatewayApiRuntime runtime,
        GatewayRequestRecord request)
    {
        if (request.State is not RequestState.Signing)
        {
            return request;
        }

        GatewayWorkerObservationResult observation =
            runtime.ResultProcessor.Observe(request);
        return observation.Request ?? request;
    }

    private static IResult SubmissionProblem(
        GatewaySubmissionError error)
    {
        return error switch
        {
            GatewaySubmissionError.RequestExpired =>
                Problem(
                    StatusCodes.Status400BadRequest,
                    "RequestExpired",
                    "The signing request has expired."),
            GatewaySubmissionError.Conflict =>
                Problem(
                    StatusCodes.Status409Conflict,
                    "RequestConflict",
                    "The signing request conflicts with durable state."),
            GatewaySubmissionError.QueueFull =>
                Problem(
                    StatusCodes.Status429TooManyRequests,
                    "QueueFull",
                    "The signing service has reached its request limit."),
            GatewaySubmissionError.TransportIdentityMismatch =>
                Forbidden(),
            GatewaySubmissionError.StorageFailed =>
                Problem(
                    StatusCodes.Status503ServiceUnavailable,
                    "SigningUnavailable",
                    "The signing service is unavailable."),
            GatewaySubmissionError.ProfileInvalid =>
                Problem(
                    StatusCodes.Status400BadRequest,
                    "ManifestInvalid",
                    "The signing profile rejected the request."),
            _ => Problem(
                StatusCodes.Status400BadRequest,
                "ArchiveInvalid",
                "The request archive is invalid."),
        };
    }

    private static IResult ApprovalProblem(
        GatewayApprovalError error)
    {
        return error switch
        {
            GatewayApprovalError.RequestNotFound => NotFound(),
            GatewayApprovalError.RequestNotPending
                or GatewayApprovalError.Conflict =>
                Problem(
                    StatusCodes.Status409Conflict,
                    "RequestConflict",
                    "The approval conflicts with durable state."),
            GatewayApprovalError.DualControlViolation =>
                Problem(
                    StatusCodes.Status403Forbidden,
                    "DualControlRequired",
                    "A distinct approver is required."),
            GatewayApprovalError.TransportIdentityMismatch =>
                Forbidden(),
            GatewayApprovalError.StorageFailed =>
                Problem(
                    StatusCodes.Status503ServiceUnavailable,
                    "SigningUnavailable",
                    "The signing service is unavailable."),
            _ => Problem(
                StatusCodes.Status400BadRequest,
                "ApprovalInvalid",
                "The approval is invalid."),
        };
    }

    private static async Task<byte[]?> ReadBoundedBodyAsync(
        Stream input,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        using MemoryStream buffer = new(
            capacity: Math.Min(maximumBytes, 64 * 1024));
        byte[] chunk = new byte[16 * 1024];
        int total = 0;
        while (true)
        {
            int count = await input.ReadAsync(
                    chunk,
                    cancellationToken)
                .ConfigureAwait(false);
            if (count is 0)
            {
                return total is 0
                    ? null
                    : buffer.ToArray();
            }

            if (count > maximumBytes - total)
            {
                return null;
            }

            await buffer.WriteAsync(
                    chunk.AsMemory(0, count),
                    cancellationToken)
                .ConfigureAwait(false);
            total += count;
        }
    }

    private static async Task<bool> CopyRequestBodyAsync(
        Stream input,
        string destinationPath,
        long maximumBytes,
        CancellationToken cancellationToken)
    {
        using FileStream output = new(
            destinationPath,
            new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                BufferSize = 64 * 1024,
                Options = FileOptions.Asynchronous
                    | FileOptions.SequentialScan
                    | FileOptions.WriteThrough,
            });
        byte[] buffer = new byte[64 * 1024];
        long total = 0;
        while (true)
        {
            int count = await input.ReadAsync(
                    buffer,
                    cancellationToken)
                .ConfigureAwait(false);
            if (count is 0)
            {
                await output.FlushAsync(cancellationToken)
                    .ConfigureAwait(false);
                return total > 0;
            }

            if (count > maximumBytes - total)
            {
                return false;
            }

            await output.WriteAsync(
                    buffer.AsMemory(0, count),
                    cancellationToken)
                .ConfigureAwait(false);
            total += count;
        }
    }

    private static bool HasExactContentType(
        HttpRequest request,
        string expected)
    {
        if (string.IsNullOrWhiteSpace(request.ContentType)
            || !MediaTypeHeaderValue.TryParse(
                request.ContentType,
                out MediaTypeHeaderValue? parsed)
            || parsed.Parameters.Count is not 0)
        {
            return false;
        }

        return string.Equals(
            parsed.MediaType.Value,
            expected,
            StringComparison.Ordinal);
    }

    private static bool TryParseRequestId(
        string value,
        out Guid requestId)
    {
        return Guid.TryParseExact(
                value,
                "D",
                out requestId)
            && requestId != Guid.Empty
            && string.Equals(
                requestId.ToString("D"),
                value,
                StringComparison.Ordinal);
    }

    private static GatewayClientIdentity GetIdentity(
        HttpContext context)
    {
        return context.Items[IdentityKey]
            as GatewayClientIdentity
            ?? throw new InvalidOperationException(
                "Gateway client identity is unavailable.");
    }

    private static DateTimeOffset WholeSecondNow(
        TimeProvider provider)
    {
        DateTimeOffset now =
            provider.GetUtcNow().ToUniversalTime();
        return new DateTimeOffset(
            now.Year,
            now.Month,
            now.Day,
            now.Hour,
            now.Minute,
            now.Second,
            TimeSpan.Zero);
    }

    private static void TryDeleteUnexecutedRequest(
        GatewayDirectoryLayout layout,
        Guid requestId)
    {
        foreach (string path in new[]
                 {
                     layout.GetPendingRequestDirectory(requestId),
                     layout.GetReadyRequestDirectory(requestId),
                 })
        {
            try
            {
                if (Directory.Exists(path)
                    && !File.GetAttributes(path).HasFlag(
                        FileAttributes.ReparsePoint))
                {
                    Directory.Delete(path, recursive: true);
                }
            }
            catch (IOException)
            {
                // Terminal durable cancellation remains authoritative.
            }
            catch (UnauthorizedAccessException)
            {
                // Terminal durable cancellation remains authoritative.
            }
        }
    }

    private static void TryDeleteOwnedDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path)
                && !File.GetAttributes(path).HasFlag(
                    FileAttributes.ReparsePoint))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (IOException)
        {
            // Bounded transport staging is reconciled on restart.
        }
        catch (UnauthorizedAccessException)
        {
            // Bounded transport staging is reconciled on restart.
        }
    }

    private static IResult NotFound()
    {
        return Problem(
            StatusCodes.Status404NotFound,
            "RequestNotFound",
            "The signing request was not found.");
    }

    private static IResult Forbidden()
    {
        return Problem(
            StatusCodes.Status403Forbidden,
            "ClientNotAuthorized",
            "The client is not authorized.");
    }

    private static IResult Problem(
        int statusCode,
        string code,
        string message)
    {
        return Results.Json(
            new GatewayProblem(code, message),
            statusCode: statusCode);
    }

    private static Task WriteProblemAsync(
        HttpContext context,
        int statusCode,
        string code,
        string message)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType =
            MediaTypeNames.Application.Json;
        return context.Response.WriteAsJsonAsync(
            new GatewayProblem(code, message),
            cancellationToken: context.RequestAborted);
    }

    private sealed class GatewayReviewTarResult(
        string trustedDirectory) : IResult
    {
        public async Task ExecuteAsync(HttpContext httpContext)
        {
            byte[] requestJson = ReadBounded(
                Path.Combine(
                    trustedDirectory,
                    GatewaySubmissionProcessor
                        .RequestJsonFileName),
                ArtifactSigningRequestJsonParser
                    .MaximumRequestJsonBytes);
            byte[] requestSignature = ReadBounded(
                Path.Combine(
                    trustedDirectory,
                    GatewaySubmissionProcessor
                        .RequestSignatureFileName),
                DetachedCmsSignatureVerifier
                    .MaximumSignatureBytes);
            httpContext.Response.StatusCode =
                StatusCodes.Status200OK;
            httpContext.Response.ContentType =
                ReviewContentType;
            using MemoryStream archive = new();
            using (TarWriter writer = new(
                       archive,
                       TarEntryFormat.Ustar,
                       leaveOpen: true))
            {
                WriteTarEntry(
                    writer,
                    GatewaySubmissionProcessor
                        .RequestJsonFileName,
                    requestJson);
                WriteTarEntry(
                    writer,
                    GatewaySubmissionProcessor
                        .RequestSignatureFileName,
                    requestSignature);
            }

            httpContext.Response.ContentLength =
                archive.Length;
            archive.Position = 0;
            await archive.CopyToAsync(
                    httpContext.Response.Body,
                    httpContext.RequestAborted)
                .ConfigureAwait(false);
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
                throw new InvalidDataException(
                    "Gateway review input is invalid.");
            }

            byte[] content =
                new byte[checked((int)input.Length)];
            input.ReadExactly(content);
            return content;
        }

        private static void WriteTarEntry(
            TarWriter writer,
            string name,
            byte[] content)
        {
            UstarTarEntry entry = new(
                TarEntryType.RegularFile,
                name)
            {
                DataStream = new MemoryStream(
                    content,
                    writable: false),
                Gid = 0,
                Uid = 0,
                GroupName = string.Empty,
                UserName = string.Empty,
                Mode =
                    UnixFileMode.UserRead
                    | UnixFileMode.UserWrite,
                ModificationTime =
                    DateTimeOffset.UnixEpoch,
            };
            writer.WriteEntry(entry);
        }
    }

    private sealed class GatewayBundleTarResult(
        GatewayResultProcessor processor,
        GatewayRequestRecord request) : IResult
    {
        public async Task ExecuteAsync(HttpContext httpContext)
        {
            using GatewayPreparedResultArchive prepared =
                processor.PrepareResultArchive(request);
            using FileStream archive =
                GatewayDirectFile.OpenRead(
                    prepared.ArchivePath);
            httpContext.Response.StatusCode =
                StatusCodes.Status200OK;
            httpContext.Response.ContentType =
                ResultContentType;
            httpContext.Response.ContentLength =
                archive.Length;
            await archive.CopyToAsync(
                    httpContext.Response.Body,
                    httpContext.RequestAborted)
                .ConfigureAwait(false);
        }
    }
}

public sealed record GatewayHealthResponse(string Status);

public sealed record GatewayAuditHeadResponse(
    string Format,
    ulong GatewaySequence,
    string GatewayEventDigest,
    ulong WorkerSequence,
    string WorkerEventDigest,
    string WorkerVersion,
    bool WorkerReady,
    bool TimestampDependencyReady,
    DateTimeOffset PublishedAt,
    DateTimeOffset ExpiresAt,
    string ReceiptSignerSpkiSha256,
    string WorkerAnchor,
    string WorkerAnchorSignature);

public sealed record GatewayProfilesResponse(
    string Format,
    IReadOnlyList<GatewayVisibleProfile> Profiles)
{
    public const string FormatIdentifier =
        "ArtifactSigningProfilesResponseV2";
}

public sealed record GatewayRequestAcceptedResponse(
    Guid RequestId,
    string RequestDigest,
    RequestState State,
    string ProjectId,
    string ProfileId,
    int ProfileVersion,
    DateTimeOffset ExpiresAt);

public sealed record GatewayDecisionAcceptedResponse(
    Guid RequestId,
    string RequestDigest,
    RequestState State);

public sealed record GatewayStatusResponse(
    Guid RequestId,
    string RequestDigest,
    RequestState State,
    GatewayResultCode ResultCode,
    string ProjectId,
    string ProfileId,
    int ProfileVersion,
    string SourceRepository,
    string SourceCommit,
    string ReleaseVersion,
    DateTimeOffset RequestedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    bool CanApprove,
    bool CanDownload);

public sealed record GatewayProblem(
    string Code,
    string Message);
