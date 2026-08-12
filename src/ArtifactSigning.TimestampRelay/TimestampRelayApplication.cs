using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Mime;
using System.Security.Cryptography;
using System.Threading.RateLimiting;

namespace ArtifactSigning.TimestampRelay;

public sealed record TimestampRelayApiRuntime(
    TimestampRelayConfiguration Configuration,
    ITimestampRelayForwarder Forwarder,
    ITimestampRelayHealthProbe HealthProbe,
    TimestampRelayRequestLimiter Limiter,
    TimestampRelayRequestLimiter HealthLimiter);

public sealed class TimestampRelayRequestLimiter :
    IDisposable
{
    private readonly ConcurrencyLimiter
        _concurrencyLimiter;
    private readonly FixedWindowRateLimiter
        _rateLimiter;

    public TimestampRelayRequestLimiter(
        int requestsPerMinute)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(
            requestsPerMinute,
            1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            requestsPerMinute,
            30);
        _concurrencyLimiter = new ConcurrencyLimiter(
            new ConcurrencyLimiterOptions
            {
                PermitLimit = 1,
                QueueLimit = 0,
                QueueProcessingOrder =
                    QueueProcessingOrder.OldestFirst,
            });
        _rateLimiter = new FixedWindowRateLimiter(
            new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = requestsPerMinute,
                QueueLimit = 0,
                QueueProcessingOrder =
                    QueueProcessingOrder.OldestFirst,
                Window = TimeSpan.FromMinutes(1),
            });
    }

    public TimestampRelayRequestLease? TryAcquire()
    {
        RateLimitLease concurrency =
            _concurrencyLimiter.AttemptAcquire();
        if (!concurrency.IsAcquired)
        {
            concurrency.Dispose();
            return null;
        }

        RateLimitLease rate =
            _rateLimiter.AttemptAcquire();
        if (!rate.IsAcquired)
        {
            rate.Dispose();
            concurrency.Dispose();
            return null;
        }

        return new TimestampRelayRequestLease(
            concurrency,
            rate);
    }

    public void Dispose()
    {
        _concurrencyLimiter.Dispose();
        _rateLimiter.Dispose();
    }
}

public sealed class TimestampRelayRequestLease :
    IDisposable
{
    private readonly RateLimitLease _concurrency;
    private readonly RateLimitLease _rate;

    internal TimestampRelayRequestLease(
        RateLimitLease concurrency,
        RateLimitLease rate)
    {
        _concurrency = concurrency;
        _rate = rate;
    }

    public void Dispose()
    {
        _rate.Dispose();
        _concurrency.Dispose();
    }
}

public static partial class TimestampRelayApplication
{
    private static readonly byte[] ReadyBody =
        "{\"Status\":\"Ready\"}"u8.ToArray();
    private static readonly byte[] NotReadyBody =
        "{\"Status\":\"NotReady\"}"u8.ToArray();
    private static readonly byte[] InvalidRequestBody =
        "{\"Code\":\"TimestampRequestInvalid\",\"Message\":\"The timestamp request is invalid.\"}"u8
            .ToArray();
    private static readonly byte[] LimitBody =
        "{\"Code\":\"TimestampLimitReached\",\"Message\":\"The timestamp relay is busy.\"}"u8
            .ToArray();
    private static readonly byte[] UnavailableBody =
        "{\"Code\":\"TimestampUnavailable\",\"Message\":\"The timestamp service is unavailable.\"}"u8
            .ToArray();

    public static void Configure(
        WebApplication application,
        TimestampRelayApiRuntime runtime)
    {
        ArgumentNullException.ThrowIfNull(application);
        ArgumentNullException.ThrowIfNull(runtime);
        application.UseExceptionHandler(handler =>
        {
            handler.Run(context => WriteFixedAsync(
                context.Response,
                StatusCodes.Status502BadGateway,
                MediaTypeNames.Application.Json,
                UnavailableBody,
                context.RequestAborted));
        });
        application.Use(async (context, next) =>
        {
            IPAddress? remote =
                context.Connection.RemoteIpAddress;
            if (remote is null
                || !runtime.Configuration
                    .AllowedClientAddresses
                    .Contains(remote))
            {
                await WriteFixedAsync(
                        context.Response,
                        StatusCodes.Status403Forbidden,
                        MediaTypeNames.Application.Json,
                        UnavailableBody,
                        context.RequestAborted)
                    .ConfigureAwait(false);
                return;
            }

            context.Response.Headers.CacheControl =
                "no-store";
            context.Response.Headers.Pragma = "no-cache";
            await next(context).ConfigureAwait(false);
        });

        application.MapGet(
            "/health/live",
            (HttpContext context) =>
                HealthAsync(
                    context,
                    runtime,
                    checkUpstream: false));
        application.MapGet(
            "/health/ready",
            (HttpContext context) =>
                HealthAsync(
                    context,
                    runtime,
                    checkUpstream: true));
        application.MapPost(
            "/timestamp",
            async (
                HttpContext context,
                ILoggerFactory loggerFactory) =>
            {
                await ForwardTimestampAsync(
                        context,
                        runtime,
                        loggerFactory.CreateLogger(
                            "TimestampRelay"))
                    .ConfigureAwait(false);
            });
        application.MapFallback(
            (HttpContext context) => WriteFixedAsync(
                context.Response,
                StatusCodes.Status404NotFound,
                MediaTypeNames.Application.Json,
                InvalidRequestBody,
                context.RequestAborted));
    }

    private static async Task HealthAsync(
        HttpContext context,
        TimestampRelayApiRuntime runtime,
        bool checkUpstream)
    {
        using TimestampRelayRequestLease? lease =
            runtime.HealthLimiter.TryAcquire();
        if (lease is null)
        {
            await WriteFixedAsync(
                    context.Response,
                    StatusCodes.Status429TooManyRequests,
                    MediaTypeNames.Application.Json,
                    NotReadyBody,
                    context.RequestAborted)
                .ConfigureAwait(false);
            return;
        }

        bool ready = !checkUpstream
            || await runtime.HealthProbe.IsReadyAsync(
                    context.RequestAborted)
                .ConfigureAwait(false);
        await WriteFixedAsync(
                context.Response,
                ready
                    ? StatusCodes.Status200OK
                    : StatusCodes
                        .Status503ServiceUnavailable,
                MediaTypeNames.Application.Json,
                ready
                    ? ReadyBody
                    : NotReadyBody,
                context.RequestAborted)
            .ConfigureAwait(false);
    }

    private static async Task ForwardTimestampAsync(
        HttpContext context,
        TimestampRelayApiRuntime runtime,
        ILogger logger)
    {
        if (!HasExactContentType(
                context.Request.ContentType))
        {
            await WriteFixedAsync(
                    context.Response,
                    StatusCodes
                        .Status415UnsupportedMediaType,
                    MediaTypeNames.Application.Json,
                    InvalidRequestBody,
                    context.RequestAborted)
                .ConfigureAwait(false);
            return;
        }

        long? contentLength =
            context.Request.ContentLength;
        if (contentLength is null or <= 0)
        {
            await WriteFixedAsync(
                    context.Response,
                    StatusCodes.Status411LengthRequired,
                    MediaTypeNames.Application.Json,
                    InvalidRequestBody,
                    context.RequestAborted)
                .ConfigureAwait(false);
            return;
        }

        if (contentLength
            > TimestampRelayUpstreamClient
                .MaximumRequestBytes)
        {
            await WriteFixedAsync(
                    context.Response,
                    StatusCodes.Status413PayloadTooLarge,
                    MediaTypeNames.Application.Json,
                    InvalidRequestBody,
                    context.RequestAborted)
                .ConfigureAwait(false);
            return;
        }

        long declaredLength = contentLength.Value;
        using TimestampRelayRequestLease? lease =
            runtime.Limiter.TryAcquire();
        if (lease is null)
        {
            await WriteFixedAsync(
                    context.Response,
                    StatusCodes.Status429TooManyRequests,
                    MediaTypeNames.Application.Json,
                    LimitBody,
                    context.RequestAborted)
                .ConfigureAwait(false);
            return;
        }

        byte[]? request = await ReadExactBodyAsync(
                context.Request.Body,
                checked((int)declaredLength),
                context.RequestAborted)
            .ConfigureAwait(false);
        if (request is null)
        {
            await WriteFixedAsync(
                    context.Response,
                    StatusCodes.Status400BadRequest,
                    MediaTypeNames.Application.Json,
                    InvalidRequestBody,
                    context.RequestAborted)
                .ConfigureAwait(false);
            return;
        }

        string digest = Convert.ToHexStringLower(
            SHA256.HashData(request));
        long started = Stopwatch.GetTimestamp();
        TimestampRelayForwardResult result =
            await runtime.Forwarder.ForwardAsync(
                    request,
                    context.RequestAborted)
                .ConfigureAwait(false);
        long durationMilliseconds = checked((long)
            Stopwatch.GetElapsedTime(started)
                .TotalMilliseconds);
        string resultCode = result.IsSuccess
            ? "Forwarded"
            : result.Error.ToString();
        TimestampAttempt(
            logger,
            digest,
            request.Length,
            durationMilliseconds,
            resultCode);
        if (!result.IsSuccess)
        {
            await WriteFixedAsync(
                    context.Response,
                    StatusCodes.Status502BadGateway,
                    MediaTypeNames.Application.Json,
                    UnavailableBody,
                    context.RequestAborted)
                .ConfigureAwait(false);
            return;
        }

        await WriteFixedAsync(
                context.Response,
                StatusCodes.Status200OK,
                TimestampRelayUpstreamClient
                    .ResponseContentType,
                result.Response,
                context.RequestAborted)
            .ConfigureAwait(false);
    }

    private static bool HasExactContentType(
        string? value)
    {
        return !string.IsNullOrWhiteSpace(value)
            && MediaTypeHeaderValue.TryParse(
                value,
                out MediaTypeHeaderValue? contentType)
            && contentType.Parameters.Count is 0
            && string.Equals(
                contentType.MediaType,
                TimestampRelayUpstreamClient
                    .RequestContentType,
                StringComparison.Ordinal);
    }

    private static async Task<byte[]?> ReadExactBodyAsync(
        Stream input,
        int length,
        CancellationToken cancellationToken)
    {
        byte[] body = new byte[length];
        int total = 0;
        while (total < body.Length)
        {
            int read = await input.ReadAsync(
                    body.AsMemory(total),
                    cancellationToken)
                .ConfigureAwait(false);
            if (read is 0)
            {
                return null;
            }

            total += read;
        }

        return await input.ReadAsync(
                    new byte[1],
                    cancellationToken)
                .ConfigureAwait(false)
            is 0
            ? body
            : null;
    }

    private static async Task WriteFixedAsync(
        HttpResponse response,
        int statusCode,
        string contentType,
        ReadOnlyMemory<byte> body,
        CancellationToken cancellationToken)
    {
        response.StatusCode = statusCode;
        response.ContentType = contentType;
        response.ContentLength = body.Length;
        await response.Body.WriteAsync(
                body,
                cancellationToken)
            .ConfigureAwait(false);
    }

    [LoggerMessage(
        EventId = 2000,
        Level = LogLevel.Information,
        Message = "Timestamp request digest {RequestDigest} size {RequestSize} duration_ms {DurationMilliseconds} result {ResultCode}.")]
    private static partial void TimestampAttempt(
        ILogger logger,
        string requestDigest,
        int requestSize,
        long durationMilliseconds,
        string resultCode);
}
