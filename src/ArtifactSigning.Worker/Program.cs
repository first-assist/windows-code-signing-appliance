using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ArtifactSigning.Worker;

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

        Environment.ExitCode = 0;
        try
        {
            WorkerServiceConfiguration configuration =
                WorkerServiceConfiguration.LoadInstalled();
            using WorkerRuntime runtime =
                WorkerRuntimeFactory.Create(configuration);

            HostApplicationBuilder builder =
                Host.CreateApplicationBuilder(
                    new HostApplicationBuilderSettings
                    {
                        Args = [],
                    });
            builder.Logging.ClearProviders();
            builder.Services.AddWindowsService(options =>
            {
                options.ServiceName = "ArtifactSigningWorker";
            });
            builder.Services.Configure<HostOptions>(options =>
            {
                options.BackgroundServiceExceptionBehavior =
                    BackgroundServiceExceptionBehavior.StopHost;
                options.ShutdownTimeout = TimeSpan.FromSeconds(15);
            });
            builder.Services.AddSingleton(runtime.Coordinator);
            builder.Services.AddHostedService<
                WorkerBackgroundService>();

            using IHost host = builder.Build();
            await host.RunAsync().ConfigureAwait(false);
            return Environment.ExitCode;
        }
        catch (Exception exception)
            when (exception is not OutOfMemoryException)
        {
            return SoftwareExitCode;
        }
    }
}
