using System.Net;
using System.Net.Http.Headers;
using Xunit;

namespace ArtifactSigning.TimestampRelay.Tests;

public sealed class TimestampRelayUpstreamTests
{
    [Fact]
    public async Task SendsOnlyFixedRequestAndAcceptsBoundReply()
    {
        using RecordingHandler handler = new(request =>
        {
            Assert.Equal(
                HttpMethod.Post,
                request.Method);
            Assert.Equal(
                "https://timestamp.example.test/timestamp",
                request.RequestUri?.AbsoluteUri);
            Assert.Equal(
                HttpVersion.Version11,
                request.Version);
            Assert.Equal(
                TimestampRelayUpstreamClient
                    .RequestContentType,
                request.Content?.Headers
                    .ContentType?.MediaType);
            Assert.Equal(
                TimestampRelayUpstreamClient
                    .ResponseContentType,
                Assert.Single(
                    request.Headers.Accept)
                    .MediaType);
            Assert.DoesNotContain(
                request.Headers,
                item => string.Equals(
                    item.Key,
                    "X-Forwarded-For",
                    StringComparison.OrdinalIgnoreCase));
            ByteArrayContent content = new([0x30, 0x01]);
            content.Headers.ContentType =
                MediaTypeHeaderValue.Parse(
                    TimestampRelayUpstreamClient
                        .ResponseContentType);
            return new HttpResponseMessage(
                HttpStatusCode.OK)
            {
                Content = content,
            };
        });
        using TimestampRelayUpstreamClient client = new(
            Configuration(),
            handler);

        TimestampRelayForwardResult result =
            await client.ForwardAsync(
                new byte[] { 0x30, 0x00 },
                TestContext.Current.CancellationToken)
                .ConfigureAwait(true);

        Assert.True(result.IsSuccess);
        Assert.Equal(
            new byte[] { 0x30, 0x01 },
            result.Response.ToArray());
        Assert.Equal(1, handler.CallCount);
    }

    [Theory]
    [InlineData(HttpStatusCode.Redirect)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    public async Task RejectsRedirectAndUpstreamFailure(
        HttpStatusCode statusCode)
    {
        using RecordingHandler handler = new(_ =>
            new HttpResponseMessage(statusCode));
        using TimestampRelayUpstreamClient client = new(
            Configuration(),
            handler);

        TimestampRelayForwardResult result =
            await client.ForwardAsync(
                new byte[] { 0x30, 0x00 },
                TestContext.Current.CancellationToken)
                .ConfigureAwait(true);

        Assert.False(result.IsSuccess);
        Assert.Equal(
            TimestampRelayForwardError.UpstreamRejected,
            result.Error);
    }

    [Fact]
    public async Task RejectsWrongOrOversizedResponse()
    {
        using RecordingHandler wrongTypeHandler = new(_ =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent([0x01]),
            });
        using TimestampRelayUpstreamClient wrongType = new(
            Configuration(),
            wrongTypeHandler);
        TimestampRelayForwardResult wrongTypeResult =
            await wrongType.ForwardAsync(
                new byte[] { 0x30, 0x00 },
                TestContext.Current.CancellationToken)
                .ConfigureAwait(true);

        Assert.Equal(
            TimestampRelayForwardError.ResponseInvalid,
            wrongTypeResult.Error);

        using RecordingHandler oversizedHandler = new(_ =>
        {
            ByteArrayContent content = new([0x01]);
            content.Headers.ContentType =
                MediaTypeHeaderValue.Parse(
                    TimestampRelayUpstreamClient
                        .ResponseContentType);
            content.Headers.ContentLength =
                TimestampRelayUpstreamClient
                    .MaximumResponseBytes + 1;
            return new HttpResponseMessage(
                HttpStatusCode.OK)
            {
                Content = content,
            };
        });
        using TimestampRelayUpstreamClient oversized = new(
            Configuration(),
            oversizedHandler);
        TimestampRelayForwardResult oversizedResult =
            await oversized.ForwardAsync(
                new byte[] { 0x30, 0x00 },
                TestContext.Current.CancellationToken)
                .ConfigureAwait(true);

        Assert.Equal(
            TimestampRelayForwardError.ResponseInvalid,
            oversizedResult.Error);
    }

    [Fact]
    public async Task MapsTimeoutToBoundedUnavailableResult()
    {
        using RecordingHandler handler = new(_ =>
            throw new TaskCanceledException());
        using TimestampRelayUpstreamClient client = new(
            Configuration(),
            handler);

        TimestampRelayForwardResult result =
            await client.ForwardAsync(
                    new byte[] { 0x30, 0x00 },
                    TestContext.Current.CancellationToken)
                .ConfigureAwait(true);

        Assert.Equal(
            TimestampRelayForwardError.UpstreamUnavailable,
            result.Error);
    }

    private static TimestampRelayConfiguration
        Configuration()
    {
        return TimestampRelayConfiguration.Parse(
            TimestampRelayConfigurationTests
                .ValidConfiguration());
    }

    private sealed class RecordingHandler(
        Func<HttpRequestMessage, HttpResponseMessage>
            callback) : HttpMessageHandler
    {
        internal int CallCount { get; private set; }

        protected override Task<HttpResponseMessage>
            SendAsync(
                HttpRequestMessage request,
                CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            return Task.FromResult(callback(request));
        }
    }
}
