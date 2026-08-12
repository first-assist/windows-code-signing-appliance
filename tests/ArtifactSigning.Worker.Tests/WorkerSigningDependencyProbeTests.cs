using System.Net;
using System.Net.Http.Headers;
using ArtifactSigning.Windows;
using Xunit;

namespace ArtifactSigning.Worker.Tests;

public sealed class WorkerSigningDependencyProbeTests
{
    [Fact]
    public void AcceptsOnlyTheAzureArcChallengeShape()
    {
        using ArcChallengeHandler handler = new(validChallenge: true);
        using WorkerSigningDependencyProbe probe = new(
            privateTimestampUris: [],
            requiresAzureArcManagedIdentity: true,
            handler);

        Assert.True(probe.IsTimestampDependencyReady());
    }

    [Fact]
    public void FailsClosedForUnexpectedArcResponse()
    {
        using ArcChallengeHandler handler = new(validChallenge: false);
        using WorkerSigningDependencyProbe probe = new(
            privateTimestampUris: [],
            requiresAzureArcManagedIdentity: true,
            handler);

        Assert.False(probe.IsTimestampDependencyReady());
    }

    private sealed class ArcChallengeHandler(bool validChallenge) :
        HttpMessageHandler
    {
        protected override HttpResponseMessage Send(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            _ = cancellationToken;
            Assert.Equal(
                AzureArcManagedIdentityEnvironment.IdentityEndpointValue,
                request.RequestUri?.GetLeftPart(UriPartial.Path));
            Assert.Contains(
                "resource=https%3A%2F%2Fmanagement.azure.com%2F",
                request.RequestUri?.Query,
                StringComparison.Ordinal);
            Assert.Equal(
                "true",
                Assert.Single(request.Headers.GetValues("Metadata")));
            HttpResponseMessage response = new(
                validChallenge
                    ? HttpStatusCode.Unauthorized
                    : HttpStatusCode.OK);
            if (validChallenge)
            {
                response.Headers.WwwAuthenticate.Add(
                    new AuthenticationHeaderValue(
                        "Basic",
                        "realm=C:\\ProgramData\\AzureConnectedMachineAgent\\Tokens\\challenge"));
            }

            return response;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(Send(request, cancellationToken));
        }
    }
}
