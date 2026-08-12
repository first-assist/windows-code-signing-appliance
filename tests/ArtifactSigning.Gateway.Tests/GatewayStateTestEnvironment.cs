using Microsoft.Data.Sqlite;

namespace ArtifactSigning.Gateway.Tests;

internal sealed class GatewayStateTestEnvironment : IDisposable
{
    internal GatewayStateTestEnvironment()
    {
        RootPath = Path.Combine(
            Path.GetTempPath(),
            $"artifact-signing-gateway-{Guid.NewGuid():N}");
        Directory.CreateDirectory(RootPath);
        Directory.CreateDirectory(
            Path.Combine(RootPath, "gateway-state"));
        Directory.CreateDirectory(
            Path.Combine(RootPath, "inbox"));
        Directory.CreateDirectory(
            Path.Combine(RootPath, "inbox", "receiving"));
        Directory.CreateDirectory(
            Path.Combine(RootPath, "inbox", "pending"));
        Directory.CreateDirectory(
            Path.Combine(RootPath, "inbox", "ready"));
        Directory.CreateDirectory(
            Path.Combine(RootPath, "status"));
        Directory.CreateDirectory(
            Path.Combine(RootPath, "output"));
        Layout = new GatewayDirectoryLayout(RootPath);
    }

    internal string RootPath { get; }

    internal GatewayDirectoryLayout Layout { get; }

    internal GatewayStateStore CreateStore()
    {
        return new GatewayStateStore(Layout);
    }

    internal void ExecuteSql(string sql)
    {
        SqliteConnectionStringBuilder builder = new()
        {
            DataSource = Layout.DatabasePath,
            Mode = SqliteOpenMode.ReadWrite,
            Pooling = false,
        };
        using SqliteConnection connection =
            new(builder.ToString());
        connection.Open();
        using SqliteCommand command = connection.CreateCommand();
#pragma warning disable CA2100 // Test-only fixed mutation statements.
        command.CommandText = sql;
#pragma warning restore CA2100
        _ = command.ExecuteNonQuery();
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(RootPath, recursive: true);
        }
        catch (IOException)
        {
            // Test cleanup is best effort.
        }
        catch (UnauthorizedAccessException)
        {
            // Test cleanup is best effort.
        }
    }
}
