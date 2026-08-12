using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http.Headers;
using ArtifactSigning.Windows;

namespace ArtifactSigning.Worker;

public sealed class WorkerSigningDependencyProbe :
    IWorkerReadinessDependencyProbe,
    IDisposable
{
    private readonly WorkerTimestampDependencyProbe? _timestampProbe;
    private readonly HttpClient? _arcClient;

    public WorkerSigningDependencyProbe(
        IEnumerable<Uri> privateTimestampUris,
        bool requiresAzureArcManagedIdentity,
        HttpMessageHandler? arcHandler = null)
    {
        ArgumentNullException.ThrowIfNull(privateTimestampUris);
        Uri[] timestamps = privateTimestampUris.Distinct().ToArray();
        if (timestamps.Length > 16
            || !requiresAzureArcManagedIdentity && arcHandler is not null)
        {
            throw new ArgumentException(
                "Signing dependency set is invalid.",
                nameof(privateTimestampUris));
        }

        _timestampProbe = timestamps.Length > 0
            ? new WorkerTimestampDependencyProbe(timestamps)
            : null;
        if (requiresAzureArcManagedIdentity)
        {
            _arcClient = arcHandler is null
                ? CreateArcClient()
                : new HttpClient(arcHandler, disposeHandler: true);
            _arcClient.Timeout = TimeSpan.FromSeconds(2);
        }
    }

    [SuppressMessage(
        "Reliability",
        "CA2000:Dispose objects before losing scope",
        Justification = "The returned HttpClient owns and disposes the handler.")]
    private static HttpClient CreateArcClient()
    {
        return new HttpClient(
            new HttpClientHandler
            {
                AllowAutoRedirect = false,
                AutomaticDecompression = DecompressionMethods.None,
                CheckCertificateRevocationList = true,
                MaxConnectionsPerServer = 1,
                UseCookies = false,
                UseProxy = false,
            },
            disposeHandler: true);
    }

    public bool IsTimestampDependencyReady()
    {
        return (_timestampProbe?.IsTimestampDependencyReady() ?? true)
            && (_arcClient is null || IsAzureArcIdentityEndpointReady());
    }

    public void Dispose()
    {
        _timestampProbe?.Dispose();
        _arcClient?.Dispose();
    }

    private bool IsAzureArcIdentityEndpointReady()
    {
        try
        {
            Uri endpoint = new(
                string.Concat(
                    AzureArcManagedIdentityEnvironment.IdentityEndpointValue,
                    "?api-version=2019-11-01&resource=",
                    Uri.EscapeDataString("https://management.azure.com/")),
                UriKind.Absolute);
            using HttpRequestMessage request = new(HttpMethod.Get, endpoint);
            request.Headers.TryAddWithoutValidation("Metadata", "true");
            using HttpResponseMessage response = _arcClient!.Send(
                request,
                HttpCompletionOption.ResponseHeadersRead);
            AuthenticationHeaderValue[] challenges = response.Headers
                .WwwAuthenticate
                .ToArray();
            return response.StatusCode is HttpStatusCode.Unauthorized
                && challenges.Length is 1
                && string.Equals(
                    challenges[0].Scheme,
                    "Basic",
                    StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(challenges[0].Parameter)
                && challenges[0].Parameter!.Length <= 1024;
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
}
