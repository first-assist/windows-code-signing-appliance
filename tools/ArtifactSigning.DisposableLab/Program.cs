using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace ArtifactSigning.DisposableLab;

internal static class Program
{
    private const string Version = "0.2.2";

    internal static async Task<int> Main(string[] args)
    {
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                return 1;
            }

            if (args is ["--version"])
            {
                await Console.Out.WriteLineAsync(
                    Version).ConfigureAwait(false);
                return 0;
            }

            if (args is ["prepare-identities"])
            {
                DisposableLabEvidence evidence =
                    DisposableIdentityProvisioner.Prepare();
                await Console.Out.WriteLineAsync(
                    JsonSerializer.Serialize(
                        evidence,
                        DisposableJson.Options))
                    .ConfigureAwait(false);
                return 0;
            }

            if (args is ["create-unsigned-bundle"])
            {
                DisposableBundleWriter.Create();
                await Console.Out.WriteLineAsync(
                    """{"ResultCode":"UNSIGNED_BUNDLE_CREATED"}""")
                    .ConfigureAwait(false);
                return 0;
            }

            if (args is ["timestamp-authority"])
            {
                HostApplicationBuilder builder =
                    Host.CreateApplicationBuilder();
                builder.Services.AddWindowsService(options =>
                    options.ServiceName =
                        "ArtifactSigningDisposableTimestamp");
                builder.Services.AddHostedService<
                    DisposableTimestampAuthority>();
                using IHost host = builder.Build();
                await host.RunAsync().ConfigureAwait(false);
                return 0;
            }

            return 64;
        }
        catch (Exception exception)
            when (exception is not OutOfMemoryException)
        {
            await Console.Error.WriteLineAsync(
                string.Create(
                    System.Globalization.CultureInfo.InvariantCulture,
                    $"DISPOSABLE_LAB_FAILED:{exception.GetType().Name}"))
                .ConfigureAwait(false);
            return 1;
        }
    }
}

internal static class DisposableJson
{
    internal static readonly JsonSerializerOptions Options =
        new()
        {
            PropertyNamingPolicy = null,
            WriteIndented = false,
        };
}
