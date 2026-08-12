namespace ArtifactSigning.Profiles;

public interface IProfileArtifactReader
{
    Stream OpenRead(string fileName);
}
