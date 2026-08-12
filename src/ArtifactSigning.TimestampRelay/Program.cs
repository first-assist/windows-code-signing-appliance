using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace ArtifactSigning.TimestampRelay;

public static class Program
{
    private const int UsageExitCode = 64;
    private const int SoftwareExitCode = 70;

    public static async Task<int> Main(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (args.Length is not 0
            || !OperatingSystem.IsLinux())
        {
            return UsageExitCode;
        }

        try
        {
            TimestampRelayConfiguration configuration =
                TimestampRelayConfiguration
                    .LoadInstalled();
            using TimestampRelayUpstreamClient upstream =
                new(configuration);
            using TimestampRelayRequestLimiter limiter =
                new(configuration.RequestsPerMinute);
            using TimestampRelayRequestLimiter healthLimiter =
                new(requestsPerMinute: 6);
            TimestampRelayApiRuntime runtime = new(
                configuration,
                upstream,
                new TimestampRelayUpstreamHealthProbe(
                    configuration),
                limiter,
                healthLimiter);
            WebApplicationBuilder builder =
                WebApplication.CreateBuilder(
                    new WebApplicationOptions
                    {
                        Args = [],
                    });
            builder.Logging.ClearProviders();
            builder.Logging.AddSimpleConsole(options =>
            {
                options.SingleLine = true;
                options.TimestampFormat =
                    "yyyy-MM-ddTHH:mm:ssZ ";
                options.UseUtcTimestamp = true;
            });
            builder.Logging.AddFilter(
                (category, level) =>
                    string.Equals(
                        category,
                        "TimestampRelay",
                        StringComparison.Ordinal)
                    && level >= LogLevel.Information);
            builder.WebHost.ConfigureKestrel(options =>
            {
                options.AddServerHeader = false;
                options.Limits.MaxRequestBodySize =
                    TimestampRelayUpstreamClient
                        .MaximumRequestBytes;
                options.Limits.MaxRequestHeadersTotalSize =
                    16 * 1024;
                options.Limits.MaxRequestHeaderCount = 32;
                options.Limits.MaxConcurrentConnections = 4;
                options.Limits
                    .MaxConcurrentUpgradedConnections = 0;
                options.Limits.KeepAliveTimeout =
                    TimeSpan.FromSeconds(15);
                options.Limits.RequestHeadersTimeout =
                    TimeSpan.FromSeconds(5);
                options.Listen(
                    configuration.BindAddress,
                    configuration.BindPort,
                    listen =>
                    {
                        listen.Protocols =
                            HttpProtocols.Http1;
                    });
            });
            WebApplication application = builder.Build();
            TimestampRelayApplication.Configure(
                application,
                runtime);
            await application.RunAsync().ConfigureAwait(false);
            return 0;
        }
        catch (Exception exception)
            when (exception is not OutOfMemoryException)
        {
            return SoftwareExitCode;
        }
    }
}
