using Microsoft.Data.Sqlite;

namespace ArtifactSigning.Worker.Tests;

internal sealed class WorkerStateTestEnvironment : IDisposable
{
    internal WorkerStateTestEnvironment()
    {
        RootPath = Path.Combine(
            Path.GetTempPath(),
            $"artifact-signing-worker-{Guid.NewGuid():N}");
        Directory.CreateDirectory(RootPath);
        Directory.CreateDirectory(Path.Combine(RootPath, "worker-state"));
        Directory.CreateDirectory(Path.Combine(RootPath, "work"));
        Directory.CreateDirectory(Path.Combine(RootPath, "output"));
        Directory.CreateDirectory(Path.Combine(RootPath, "quarantine"));
        Layout = new WorkerDirectoryLayout(RootPath);
    }

    internal string RootPath { get; }

    internal WorkerDirectoryLayout Layout { get; }

    internal WorkerStateStore CreateStore()
    {
        return new WorkerStateStore(Layout);
    }

    internal void CreateWorkDirectory(Guid requestId)
    {
        Directory.CreateDirectory(Layout.GetWorkDirectory(requestId));
    }

    internal void ExecuteSql(string sql)
    {
        SqliteConnectionStringBuilder builder = new()
        {
            DataSource = Layout.DatabasePath,
            Mode = SqliteOpenMode.ReadWrite,
            Pooling = false,
        };
        using SqliteConnection connection = new(builder.ToString());
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
