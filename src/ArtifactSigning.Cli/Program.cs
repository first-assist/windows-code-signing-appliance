namespace ArtifactSigning.Cli;

internal static class Program
{
    public static Task<int> Main(string[] args)
    {
        return CliApplication.RunAsync(
            args,
            Console.Out,
            Console.Error,
            Console.In,
            TimeProvider.System,
            CancellationToken.None);
    }
}
