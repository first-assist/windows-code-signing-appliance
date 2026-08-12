using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http.Headers;
using ArtifactSigning.TimestampRelay;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Xunit;

namespace ArtifactSigning.TimestampRelay.Tests;

public sealed class TimestampRelayApplicationTests
{
    [Fact]
    [SuppressMessage(
        "Reliability",
        "CA2007:Consider calling ConfigureAwait on the awaited task",
        Justification =
            "await using invokes WebApplication.DisposeAsync directly in the test synchronization context.")]
    public async Task EnforcesClientMediaBoundsRateAndFixedHealth()
    {
        TimestampRelayConfiguration configuration =
            Configuration(requestsPerMinute: 1);
        using TimestampRelayRequestLimiter limiter = new(
            configuration.RequestsPerMinute);
        using TimestampRelayRequestLimiter healthLimiter =
            new(requestsPerMinute: 6);
        IPAddress remote =
            IPAddress.Parse("10.20.30.41");
        WebApplication startedApplication =
            await StartAsync(
                configuration,
                new SuccessfulForwarder(),
                new FixedHealthProbe(ready: true),
                limiter,
                healthLimiter,
                () => remote)
                .ConfigureAwait(true);
        await using WebApplication application =
            startedApplication;
        using HttpClient client =
            application.GetTestClient();

        using HttpResponseMessage health =
            await client.GetAsync(
                new Uri(
                    "/health/ready",
                    UriKind.Relative),
                TestContext.Current.CancellationToken)
                .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, health.StatusCode);
        Assert.Equal(
            "application/json",
            health.Content.Headers.ContentType?.ToString());
        Assert.Equal(
            "{\"Status\":\"Ready\"}",
            await health.Content.ReadAsStringAsync(
                    TestContext.Current.CancellationToken)
                .ConfigureAwait(true));

        using HttpResponseMessage success =
            await SendTimestampAsync(client)
                .ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, success.StatusCode);
        Assert.Equal(
            TimestampRelayUpstreamClient
                .ResponseContentType,
            success.Content.Headers.ContentType?.ToString());
        Assert.Equal(
            new byte[] { 0x30, 0x01 },
            await success.Content.ReadAsByteArrayAsync(
                    TestContext.Current.CancellationToken)
                .ConfigureAwait(true));

        using HttpResponseMessage limited =
            await SendTimestampAsync(client)
                .ConfigureAwait(true);
        Assert.Equal(
            HttpStatusCode.TooManyRequests,
            limited.StatusCode);

        using ByteArrayContent wrong = new([0x30, 0x00]);
        wrong.Headers.ContentType =
            MediaTypeHeaderValue.Parse(
                "application/octet-stream");
        using HttpResponseMessage wrongType =
            await client.PostAsync(
                new Uri(
                    "/timestamp",
                    UriKind.Relative),
                wrong,
                TestContext.Current.CancellationToken)
                .ConfigureAwait(true);
        Assert.Equal(
            HttpStatusCode.UnsupportedMediaType,
            wrongType.StatusCode);

        remote = IPAddress.Parse("10.20.30.42");
        using HttpResponseMessage denied =
            await client.GetAsync(
                new Uri(
                    "/health/live",
                    UriKind.Relative),
                TestContext.Current.CancellationToken)
                .ConfigureAwait(true);
        Assert.Equal(
            HttpStatusCode.Forbidden,
            denied.StatusCode);
    }

    [Fact]
    [SuppressMessage(
        "Reliability",
        "CA2025:Do not pass IDisposable instances into unawaited tasks",
        Justification =
            "Both client operations are awaited before their using scopes end.")]
    [SuppressMessage(
        "Reliability",
        "CA2007:Consider calling ConfigureAwait on the awaited task",
        Justification =
            "await using invokes WebApplication.DisposeAsync directly in the test synchronization context.")]
    public async Task RejectsConcurrentRequestWithoutQueueing()
    {
        TimestampRelayConfiguration configuration =
            Configuration(requestsPerMinute: 2);
        using TimestampRelayRequestLimiter limiter = new(
            configuration.RequestsPerMinute);
        using TimestampRelayRequestLimiter healthLimiter =
            new(requestsPerMinute: 6);
        BlockingForwarder forwarder = new();
        WebApplication startedApplication =
            await StartAsync(
                configuration,
                forwarder,
                new FixedHealthProbe(ready: true),
                limiter,
                healthLimiter,
                () => IPAddress.Parse("10.20.30.41"))
                .ConfigureAwait(true);
        await using WebApplication application =
            startedApplication;
        using HttpClient firstClient =
            application.GetTestClient();
        using HttpClient secondClient =
            application.GetTestClient();

        Task<HttpResponseMessage> first =
            SendTimestampAsync(firstClient);
        await forwarder.Entered.Task.WaitAsync(
                TestContext.Current.CancellationToken)
            .ConfigureAwait(true);
        using HttpResponseMessage second =
            await SendTimestampAsync(secondClient)
                .ConfigureAwait(true);
        Assert.Equal(
            HttpStatusCode.TooManyRequests,
            second.StatusCode);
        forwarder.Release.TrySetResult();
        using HttpResponseMessage firstResponse =
            await first.ConfigureAwait(true);
        Assert.Equal(
            HttpStatusCode.OK,
            firstResponse.StatusCode);
    }

    private static async Task<WebApplication> StartAsync(
        TimestampRelayConfiguration configuration,
        ITimestampRelayForwarder forwarder,
        ITimestampRelayHealthProbe health,
        TimestampRelayRequestLimiter limiter,
        TimestampRelayRequestLimiter healthLimiter,
        Func<IPAddress> remoteAddress)
    {
        WebApplicationBuilder builder =
            WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        WebApplication application = builder.Build();
        application.Use(async (context, next) =>
        {
            context.Connection.RemoteIpAddress =
                remoteAddress();
            await next(context).ConfigureAwait(false);
        });
        TimestampRelayApplication.Configure(
            application,
            new TimestampRelayApiRuntime(
                configuration,
                forwarder,
                health,
                limiter,
                healthLimiter));
        await application.StartAsync(
                TestContext.Current.CancellationToken)
            .ConfigureAwait(false);
        return application;
    }

    private static async Task<HttpResponseMessage>
        SendTimestampAsync(HttpClient client)
    {
        using ByteArrayContent content =
            new([0x30, 0x00]);
        content.Headers.ContentType =
            MediaTypeHeaderValue.Parse(
                TimestampRelayUpstreamClient
                    .RequestContentType);
        HttpResponseMessage response =
            await client.PostAsync(
                new Uri(
                    "/timestamp",
                    UriKind.Relative),
                content,
                TestContext.Current.CancellationToken)
                .ConfigureAwait(false);
        return response;
    }

    private static TimestampRelayConfiguration
        Configuration(int requestsPerMinute)
    {
        return TimestampRelayConfiguration.Parse(
            TimestampRelayConfigurationTests
                .ValidConfiguration(
                    requestsPerMinute));
    }

    private sealed class SuccessfulForwarder :
        ITimestampRelayForwarder
    {
        public ValueTask<TimestampRelayForwardResult>
            ForwardAsync(
                ReadOnlyMemory<byte> request,
                CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(
                new TimestampRelayForwardResult(
                    TimestampRelayForwardError.None,
                    new byte[] { 0x30, 0x01 }));
        }
    }

    private sealed class BlockingForwarder :
        ITimestampRelayForwarder
    {
        internal TaskCompletionSource Entered { get; } =
            new(
                TaskCreationOptions
                    .RunContinuationsAsynchronously);

        internal TaskCompletionSource Release { get; } =
            new(
                TaskCreationOptions
                    .RunContinuationsAsynchronously);

        public async ValueTask<TimestampRelayForwardResult>
            ForwardAsync(
                ReadOnlyMemory<byte> request,
                CancellationToken cancellationToken)
        {
            Entered.TrySetResult();
            await Release.Task.WaitAsync(
                    cancellationToken)
                .ConfigureAwait(false);
            return new TimestampRelayForwardResult(
                TimestampRelayForwardError.None,
                new byte[] { 0x30, 0x01 });
        }
    }

    private sealed class FixedHealthProbe(bool ready) :
        ITimestampRelayHealthProbe
    {
        public ValueTask<bool> IsReadyAsync(
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(ready);
        }
    }
}
