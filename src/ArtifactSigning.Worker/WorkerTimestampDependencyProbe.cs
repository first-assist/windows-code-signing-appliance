using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http.Headers;

namespace ArtifactSigning.Worker;

public sealed class WorkerTimestampDependencyProbe :
    IWorkerReadinessDependencyProbe,
    IDisposable
{
    private static readonly byte[] ExpectedBody =
        "{\"Status\":\"Ready\"}"u8.ToArray();

    private readonly IReadOnlyList<Uri> _healthUris;
    private readonly HttpClient _client;

    public WorkerTimestampDependencyProbe(
        IEnumerable<Uri> timestampUris,
        HttpMessageHandler? handler = null)
    {
        ArgumentNullException.ThrowIfNull(timestampUris);
        Uri[] healthUris = timestampUris
            .Select(CreateHealthUri)
            .Distinct()
            .ToArray();
        if (healthUris.Length is 0 or > 16)
        {
            throw new ArgumentException(
                "Timestamp dependency set is invalid.",
                nameof(timestampUris));
        }

        _healthUris = Array.AsReadOnly(healthUris);
        _client = handler is null
            ? CreateDefaultClient()
            : new HttpClient(
                handler,
                disposeHandler: true);
        _client.Timeout = TimeSpan.FromSeconds(3);
    }

    [SuppressMessage(
        "Reliability",
        "CA2000:Dispose objects before losing scope",
        Justification =
            "The returned HttpClient owns and disposes the handler.")]
    private static HttpClient CreateDefaultClient()
    {
        return new HttpClient(
            new HttpClientHandler
            {
                AllowAutoRedirect = false,
                AutomaticDecompression =
                    DecompressionMethods.None,
                CheckCertificateRevocationList = true,
                MaxConnectionsPerServer = 1,
                UseCookies = false,
                UseProxy = false,
            },
            disposeHandler: true);
    }

    public bool IsTimestampDependencyReady()
    {
        try
        {
            foreach (Uri healthUri in _healthUris)
            {
                using HttpRequestMessage request = new(
                    HttpMethod.Get,
                    healthUri);
                using HttpResponseMessage response =
                    _client.Send(
                        request,
                        HttpCompletionOption
                            .ResponseHeadersRead);
                if (response.StatusCode
                        is not HttpStatusCode.OK
                    || response.Content.Headers.ContentLength
                        != ExpectedBody.Length
                    || !HasExactJsonContentType(
                        response.Content.Headers
                            .ContentType))
                {
                    return false;
                }

                using Stream body =
                    response.Content.ReadAsStream();
                byte[] content =
                    new byte[ExpectedBody.Length];
                body.ReadExactly(content);
                if (body.ReadByte() is not -1
                    || !content.AsSpan()
                        .SequenceEqual(ExpectedBody))
                {
                    return false;
                }
            }

            return true;
        }
        catch (Exception exception)
            when (exception is HttpRequestException
                or IOException
                or TaskCanceledException
                or InvalidOperationException)
        {
            return false;
        }
    }

    public void Dispose()
    {
        _client.Dispose();
    }

    private static Uri CreateHealthUri(
        Uri timestampUri)
    {
        ArgumentNullException.ThrowIfNull(timestampUri);
        if (!timestampUri.IsAbsoluteUri
            || timestampUri.Scheme is not (
                "http" or "https")
            || string.IsNullOrWhiteSpace(
                timestampUri.Host))
        {
            throw new ArgumentException(
                "Timestamp dependency URI is invalid.",
                nameof(timestampUri));
        }

        UriBuilder builder = new(timestampUri)
        {
            Path = "/health/ready",
            Query = string.Empty,
            Fragment = string.Empty,
            UserName = string.Empty,
            Password = string.Empty,
        };
        return builder.Uri;
    }

    private static bool HasExactJsonContentType(
        MediaTypeHeaderValue? contentType)
    {
        return contentType is not null
            && contentType.Parameters.Count is 0
            && string.Equals(
                contentType.MediaType,
                "application/json",
                StringComparison.Ordinal);
    }
}
