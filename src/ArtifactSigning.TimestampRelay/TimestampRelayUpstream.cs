using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace ArtifactSigning.TimestampRelay;

public enum TimestampRelayForwardError
{
    None,
    UpstreamUnavailable,
    UpstreamRejected,
    ResponseInvalid,
}

public sealed record TimestampRelayForwardResult(
    TimestampRelayForwardError Error,
    ReadOnlyMemory<byte> Response)
{
    public bool IsSuccess =>
        Error is TimestampRelayForwardError.None
        && !Response.IsEmpty;
}

public interface ITimestampRelayForwarder
{
    ValueTask<TimestampRelayForwardResult> ForwardAsync(
        ReadOnlyMemory<byte> request,
        CancellationToken cancellationToken);
}

public sealed class TimestampRelayUpstreamClient :
    ITimestampRelayForwarder,
    IDisposable
{
    public const string RequestContentType =
        "application/timestamp-query";
    public const string ResponseContentType =
        "application/timestamp-reply";
    public const int MaximumRequestBytes = 64 * 1024;
    public const int MaximumResponseBytes =
        1024 * 1024;

    private readonly Uri _upstreamUrl;
    private readonly HttpClient _client;

    public TimestampRelayUpstreamClient(
        TimestampRelayConfiguration configuration,
        HttpMessageHandler? handler = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        _upstreamUrl = configuration.UpstreamUrl;
        _client = handler is null
            ? CreatePinnedClient(configuration)
            : new HttpClient(
                handler,
                disposeHandler: true);
        _client.Timeout = configuration.TotalTimeout;
    }

    public async ValueTask<TimestampRelayForwardResult>
        ForwardAsync(
            ReadOnlyMemory<byte> request,
            CancellationToken cancellationToken)
    {
        if (request.IsEmpty
            || request.Length > MaximumRequestBytes)
        {
            throw new ArgumentException(
                "Timestamp request is empty or oversized.",
                nameof(request));
        }

        try
        {
            using HttpRequestMessage message = new(
                HttpMethod.Post,
                _upstreamUrl)
            {
                Version = HttpVersion.Version11,
                VersionPolicy =
                    HttpVersionPolicy.RequestVersionExact,
                Content = new ByteArrayContent(
                    request.ToArray()),
            };
            message.Content.Headers.ContentType =
                MediaTypeHeaderValue.Parse(
                    RequestContentType);
            message.Headers.Accept.Add(
                new MediaTypeWithQualityHeaderValue(
                    ResponseContentType));
            using HttpResponseMessage response =
                await _client.SendAsync(
                        message,
                        HttpCompletionOption
                            .ResponseHeadersRead,
                        cancellationToken)
                    .ConfigureAwait(false);
            if (response.StatusCode
                is not HttpStatusCode.OK)
            {
                return Failure(
                    TimestampRelayForwardError
                        .UpstreamRejected);
            }

            if (!HasExactContentType(
                    response.Content.Headers
                        .ContentType))
            {
                return Failure(
                    TimestampRelayForwardError
                        .ResponseInvalid);
            }

            long? declaredLength =
                response.Content.Headers.ContentLength;
            if (declaredLength is 0
                || declaredLength
                    > MaximumResponseBytes)
            {
                return Failure(
                    TimestampRelayForwardError
                        .ResponseInvalid);
            }

            using Stream input =
                await response.Content.ReadAsStreamAsync(
                        cancellationToken)
                    .ConfigureAwait(false);
            using MemoryStream output = new();
            byte[] buffer = new byte[16 * 1024];
            int total = 0;
            while (true)
            {
                int read = await input.ReadAsync(
                        buffer,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (read is 0)
                {
                    if (total is 0
                        || declaredLength.HasValue
                            && total
                                != declaredLength.Value)
                    {
                        return Failure(
                            TimestampRelayForwardError
                                .ResponseInvalid);
                    }

                    return new TimestampRelayForwardResult(
                        TimestampRelayForwardError.None,
                        output.ToArray());
                }

                if (read > MaximumResponseBytes - total)
                {
                    return Failure(
                        TimestampRelayForwardError
                            .ResponseInvalid);
                }

                await output.WriteAsync(
                        buffer.AsMemory(0, read),
                        cancellationToken)
                    .ConfigureAwait(false);
                total += read;
            }
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
            when (exception is HttpRequestException
                or IOException
                or TaskCanceledException
                or InvalidOperationException)
        {
            return Failure(
                TimestampRelayForwardError
                    .UpstreamUnavailable);
        }
    }

    public void Dispose()
    {
        _client.Dispose();
    }

    [SuppressMessage(
        "Reliability",
        "CA2000:Dispose objects before losing scope",
        Justification =
            "The returned HttpClient owns and disposes the pinned sockets handler.")]
    private static HttpClient CreatePinnedClient(
        TimestampRelayConfiguration configuration)
    {
        SocketsHttpHandler handler = new()
        {
            AllowAutoRedirect = false,
            AutomaticDecompression =
                DecompressionMethods.None,
            ConnectTimeout = configuration.ConnectTimeout,
            MaxConnectionsPerServer = 1,
            MaxResponseHeadersLength = 16,
            PooledConnectionLifetime =
                TimeSpan.FromMinutes(5),
            UseCookies = false,
            UseProxy = false,
            SslOptions = new SslClientAuthenticationOptions
            {
                CertificateRevocationCheckMode =
                    X509RevocationMode.Online,
                EnabledSslProtocols = SslProtocols.None,
            },
        };
        handler.ConnectCallback =
            (context, cancellationToken) =>
                ConnectPinnedAsync(
                    context,
                    configuration,
                    cancellationToken);
        return new HttpClient(
            handler,
            disposeHandler: true);
    }

    [SuppressMessage(
        "Reliability",
        "CA2000:Dispose objects before losing scope",
        Justification =
            "A successful NetworkStream owns the connected socket; failed attempts dispose it locally.")]
    private static async ValueTask<Stream>
        ConnectPinnedAsync(
            SocketsHttpConnectionContext context,
            TimestampRelayConfiguration configuration,
            CancellationToken cancellationToken)
    {
        if (!string.Equals(
                context.DnsEndPoint.Host,
                configuration.UpstreamUrl.IdnHost,
                StringComparison.OrdinalIgnoreCase)
            || context.DnsEndPoint.Port
                != configuration.UpstreamUrl.Port)
        {
            throw new HttpRequestException(
                "Timestamp destination is outside policy.");
        }

        foreach (IPAddress address
                 in configuration.UpstreamAddresses)
        {
            Socket socket = new(
                address.AddressFamily,
                SocketType.Stream,
                ProtocolType.Tcp)
            {
                NoDelay = true,
            };
            try
            {
                await socket.ConnectAsync(
                        new IPEndPoint(
                            address,
                            context.DnsEndPoint.Port),
                        cancellationToken)
                    .ConfigureAwait(false);
                return new NetworkStream(
                    socket,
                    ownsSocket: true);
            }
            catch (Exception exception)
                when (exception is SocketException
                    or OperationCanceledException)
            {
                socket.Dispose();
                if (cancellationToken
                    .IsCancellationRequested)
                {
                    throw;
                }
            }
        }

        throw new HttpRequestException(
            "Timestamp destination is unavailable.");
    }

    private static bool HasExactContentType(
        MediaTypeHeaderValue? contentType)
    {
        return contentType is not null
            && contentType.Parameters.Count is 0
            && string.Equals(
                contentType.MediaType,
                ResponseContentType,
                StringComparison.Ordinal);
    }

    private static TimestampRelayForwardResult Failure(
        TimestampRelayForwardError error)
    {
        return new TimestampRelayForwardResult(
            error,
            ReadOnlyMemory<byte>.Empty);
    }
}

public interface ITimestampRelayHealthProbe
{
    ValueTask<bool> IsReadyAsync(
        CancellationToken cancellationToken);
}

public sealed class TimestampRelayUpstreamHealthProbe :
    ITimestampRelayHealthProbe
{
    private readonly TimestampRelayConfiguration
        _configuration;

    public TimestampRelayUpstreamHealthProbe(
        TimestampRelayConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        _configuration = configuration;
    }

    public async ValueTask<bool> IsReadyAsync(
        CancellationToken cancellationToken)
    {
        using CancellationTokenSource timeout =
            CancellationTokenSource
                .CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(
            _configuration.ConnectTimeout);
        foreach (IPAddress address
                 in _configuration.UpstreamAddresses)
        {
            try
            {
                using Socket socket = new(
                    address.AddressFamily,
                    SocketType.Stream,
                    ProtocolType.Tcp)
                {
                    NoDelay = true,
                };
                await socket.ConnectAsync(
                        new IPEndPoint(
                            address,
                            _configuration
                                .UpstreamUrl.Port),
                        timeout.Token)
                    .ConfigureAwait(false);
                if (_configuration.UpstreamUrl.Scheme
                    == Uri.UriSchemeHttps)
                {
                    using NetworkStream network = new(
                        socket,
                        ownsSocket: false);
                    using SslStream tls = new(network);
                    await tls.AuthenticateAsClientAsync(
                            new SslClientAuthenticationOptions
                            {
                                TargetHost = _configuration
                                    .UpstreamUrl.IdnHost,
                                CertificateRevocationCheckMode =
                                    X509RevocationMode.Online,
                                EnabledSslProtocols =
                                    SslProtocols.None,
                            },
                            timeout.Token)
                        .ConfigureAwait(false);
                }

                return true;
            }
            catch (Exception exception)
                when (exception is SocketException
                    or AuthenticationException
                    or IOException
                    or OperationCanceledException)
            {
                if (cancellationToken
                    .IsCancellationRequested)
                {
                    throw;
                }
            }
        }

        return false;
    }
}
