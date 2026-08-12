using System.Security.Authentication;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Xunit;

namespace ArtifactSigning.Gateway.Tests;

public sealed class GatewayProgramTests
{
    [Fact]
    public void MutualTlsRequiresClientCertificateAndOnlineRevocation()
    {
        HttpsConnectionAdapterOptions options = new();

        Program.ConfigureMutualTls(options);

        Assert.Equal(
            ClientCertificateMode.RequireCertificate,
            options.ClientCertificateMode);
        Assert.Equal(SslProtocols.None, options.SslProtocols);
        Assert.True(options.CheckCertificateRevocation);
    }

    [Fact]
    public void MutualTlsRejectsNullOptions()
    {
        Assert.Throws<ArgumentNullException>(
            () => Program.ConfigureMutualTls(null!));
    }
}
