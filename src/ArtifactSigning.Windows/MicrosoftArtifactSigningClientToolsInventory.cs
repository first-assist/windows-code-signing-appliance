using System.Security.Cryptography;
using System.Text;

namespace ArtifactSigning.Windows;

public static class MicrosoftArtifactSigningClientToolsInventory
{
    public const int MaximumFiles = 128;

    public static bool TryComputeSha256(
        string trustedAbsoluteDirectory,
        out string? inventorySha256)
    {
        inventorySha256 = null;
        if (string.IsNullOrWhiteSpace(trustedAbsoluteDirectory)
            || !Path.IsPathFullyQualified(trustedAbsoluteDirectory))
        {
            return false;
        }

        try
        {
            FileAttributes attributes = File.GetAttributes(
                trustedAbsoluteDirectory);
            if (!attributes.HasFlag(FileAttributes.Directory)
                || attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                return false;
            }

            string[] entries = Directory.EnumerateFileSystemEntries(
                    trustedAbsoluteDirectory,
                    "*",
                    SearchOption.TopDirectoryOnly)
                .ToArray();
            if (entries.Length is 0 or > MaximumFiles
                || entries.Any(Directory.Exists))
            {
                return false;
            }

            List<(string Name, ArtifactFileSnapshot Snapshot)> files = [];
            foreach (string path in entries)
            {
                string name = Path.GetFileName(path);
                if (!IsSafeLeafName(name)
                    || !ArtifactFileSnapshot.TryCreate(
                        path,
                        out ArtifactFileSnapshot? snapshot)
                    || snapshot is null)
                {
                    return false;
                }

                files.Add((name, snapshot));
            }

            files.Sort((left, right) =>
                StringComparer.Ordinal.Compare(left.Name, right.Name));
            using IncrementalHash hash = IncrementalHash.CreateHash(
                HashAlgorithmName.SHA256);
            foreach ((string name, ArtifactFileSnapshot snapshot) in files)
            {
                hash.AppendData(Encoding.UTF8.GetBytes(name));
                hash.AppendData([0]);
                hash.AppendData(Encoding.ASCII.GetBytes(
                    snapshot.Size.ToString(
                        System.Globalization.CultureInfo.InvariantCulture)));
                hash.AppendData([0]);
                hash.AppendData(Encoding.ASCII.GetBytes(snapshot.Sha256));
                hash.AppendData([(byte)'\n']);
            }

            inventorySha256 = Convert.ToHexStringLower(
                hash.GetHashAndReset());
            return true;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (NotSupportedException)
        {
            return false;
        }
    }

    private static bool IsSafeLeafName(string name)
    {
        return name.Length is > 0 and <= 128
            && name is not "." and not ".."
            && name.All(character =>
                char.IsAsciiLetterOrDigit(character)
                || character is '.' or '-' or '_');
    }
}
