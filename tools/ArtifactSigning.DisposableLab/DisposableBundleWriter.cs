using ArtifactSigning.TestProfile;
using ArtifactSigning.TestProfile.Tests;

namespace ArtifactSigning.DisposableLab;

internal static class DisposableBundleWriter
{
    internal static void Create()
    {
        if (Directory.Exists(DisposableLabPaths.Bundle))
        {
            throw new InvalidOperationException(
                "The disposable unsigned bundle already exists.");
        }

        DisposableLabEvidence evidence = LoadEvidence();
        ExampleBundleTestData bundle = ExampleBundleTestData.Create(
            signerThumbprint:
                evidence.Authenticode.Thumbprint);
        Directory.CreateDirectory(
            DisposableLabPaths.Bundle);
        foreach (ArtifactSigning.Profiles
                     .SigningProfileArtifactDefinition artifact
                 in ExampleEndpointBundleV1.Instance
                     .Descriptor.Artifacts)
        {
            File.WriteAllBytes(
                Path.Combine(
                    DisposableLabPaths.Bundle,
                    artifact.FileName),
                bundle.ReadAllBytes(artifact.FileName));
        }
    }

    private static DisposableLabEvidence LoadEvidence()
    {
        byte[] content = File.ReadAllBytes(
            DisposableLabPaths.Evidence);
        DisposableLabEvidence? evidence =
            System.Text.Json.JsonSerializer.Deserialize<
                DisposableLabEvidence>(
                content,
                DisposableJson.Options);
        if (evidence is null
            || evidence.Format
                != "ArtifactSigningDisposableLabEvidenceV1")
        {
            throw new InvalidDataException(
                "Disposable identity evidence is invalid.");
        }

        return evidence;
    }
}
