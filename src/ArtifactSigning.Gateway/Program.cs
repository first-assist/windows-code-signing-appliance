using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ArtifactSigning.Protocol;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ArtifactSigning.Gateway;

public static class Program
{
    private const int UsageExitCode = 64;
    private const int SoftwareExitCode = 70;

    public static async Task<int> Main(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (args.Length is not 0 || !OperatingSystem.IsWindows())
        {
            return UsageExitCode;
        }

        try
        {
            GatewayServiceConfiguration configuration =
                GatewayServiceConfiguration.LoadInstalled();
            using GatewayInstalledRuntime runtime =
                GatewayRuntimeFactory.Create(configuration);
            GatewayStartupReconciliationOutcome reconciliation =
                await runtime.Reconciler.ReconcileAsync(
                        CancellationToken.None)
                    .ConfigureAwait(false);
            if (reconciliation is not
                GatewayStartupReconciliationOutcome.Ready)
            {
                return SoftwareExitCode;
            }

            WebApplicationBuilder builder =
                WebApplication.CreateBuilder(
                    new WebApplicationOptions
                    {
                        Args = [],
                    });
            builder.Logging.ClearProviders();
            builder.Services.AddWindowsService(options =>
            {
                options.ServiceName =
                    "ArtifactSigningGateway";
            });
            builder.Services.Configure<HostOptions>(options =>
            {
                options.BackgroundServiceExceptionBehavior =
                    BackgroundServiceExceptionBehavior.StopHost;
                options.ShutdownTimeout =
                    TimeSpan.FromSeconds(15);
            });
            GatewayApiApplication.AddGatewayApiServices(
                builder.Services);
            builder.WebHost.ConfigureKestrel(options =>
            {
                options.AddServerHeader = false;
                options.Limits.MaxRequestBodySize =
                    GatewayApiApplication
                        .MaximumRequestBodyBytes;
                options.Limits.MaxRequestHeadersTotalSize =
                    16 * 1024;
                options.Limits.MaxRequestHeaderCount = 64;
                options.Limits.MaxConcurrentConnections = 8;
                options.Limits
                    .MaxConcurrentUpgradedConnections = 0;
                options.Limits.KeepAliveTimeout =
                    TimeSpan.FromSeconds(30);
                options.Limits.RequestHeadersTimeout =
                    TimeSpan.FromSeconds(15);
                options.Listen(
                    configuration.ListenAddress,
                    configuration.ListenPort,
                    listen =>
                    {
                        listen.Protocols =
                            HttpProtocols.Http1AndHttp2;
                        listen.UseHttps(https =>
                        {
                            https.ServerCertificate =
                                runtime.ServerCertificate;
                            ConfigureMutualTls(https);
                            https.ClientCertificateValidation =
                                (certificate, _, errors) =>
                                    ValidateClientCertificate(
                                        certificate,
                                        errors,
                                        runtime.Api
                                            .Authorization);
                        });
                    });
            });

            WebApplication application = builder.Build();
            GatewayApiApplication.Configure(
                application,
                runtime.Api);
            await application.RunAsync().ConfigureAwait(false);
            return 0;
        }
        catch (Exception exception)
            when (exception is not OutOfMemoryException)
        {
            return SoftwareExitCode;
        }
    }

    internal static void ConfigureMutualTls(
        HttpsConnectionAdapterOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.ClientCertificateMode =
            ClientCertificateMode.RequireCertificate;
        options.SslProtocols = SslProtocols.None;
        options.CheckCertificateRevocation = true;
    }

    private static bool ValidateClientCertificate(
        X509Certificate2? certificate,
        SslPolicyErrors errors,
        GatewayAuthorizationRegistry authorization)
    {
        if (certificate is null
            || errors is not SslPolicyErrors.None)
        {
            return false;
        }

        try
        {
            GatewayClientIdentity identity = new(
                CertificateIdentity.ComputeCertificateSha256(
                    certificate),
                CertificateIdentity
                    .ComputeSubjectPublicKeyInfoSha256(
                        certificate));
            return authorization.IsAllowedClient(identity);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}
