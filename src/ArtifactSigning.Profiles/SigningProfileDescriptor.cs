using System.Collections.ObjectModel;

namespace ArtifactSigning.Profiles;

public sealed class SigningProfileDescriptor
{
    public SigningProfileDescriptor(
        SigningProfileIdentity identity,
        IEnumerable<string> allowedProjectIds,
        IEnumerable<string> allowedSourceRepositories,
        IEnumerable<SigningProfileArtifactDefinition> artifacts,
        IEnumerable<string> allowedSignerPolicyIds,
        IEnumerable<string> allowedTimestampPolicyIds,
        long maximumRequestBytes)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(allowedProjectIds);
        ArgumentNullException.ThrowIfNull(allowedSourceRepositories);
        ArgumentNullException.ThrowIfNull(artifacts);
        ArgumentNullException.ThrowIfNull(allowedSignerPolicyIds);
        ArgumentNullException.ThrowIfNull(allowedTimestampPolicyIds);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumRequestBytes);

        string[] projects = CopyIdentifiers(
            allowedProjectIds,
            nameof(allowedProjectIds),
            maximumCount: 16);
        string[] sourceRepositories = CopySourceRepositories(
            allowedSourceRepositories,
            nameof(allowedSourceRepositories));
        SigningProfileArtifactDefinition[] artifactDefinitions = artifacts.ToArray();
        string[] signerPolicies = CopyIdentifiers(
            allowedSignerPolicyIds,
            nameof(allowedSignerPolicyIds),
            maximumCount: 16);
        string[] timestampPolicies = CopyIdentifiers(
            allowedTimestampPolicyIds,
            nameof(allowedTimestampPolicyIds),
            maximumCount: 16);

        if (artifactDefinitions.Length is 0 or > 64)
        {
            throw new ArgumentException(
                "A profile must define from one through sixty-four artifacts.",
                nameof(artifacts));
        }

        if (artifactDefinitions.Any(artifact => artifact is null))
        {
            throw new ArgumentException(
                "Artifact definitions cannot contain null values.",
                nameof(artifacts));
        }

        if (artifactDefinitions.Select(artifact => artifact.Role).Distinct(
                StringComparer.Ordinal).Count() != artifactDefinitions.Length
            || artifactDefinitions.Select(artifact => artifact.FileName).Distinct(
                StringComparer.Ordinal).Count() != artifactDefinitions.Length)
        {
            throw new ArgumentException(
                "Artifact roles and filenames must be unique.",
                nameof(artifacts));
        }

        if (artifactDefinitions.Count(
                artifact => artifact.Kind is SigningProfileArtifactKind.JsonManifest) is not 1)
        {
            throw new ArgumentException(
                "A profile must define exactly one JSON manifest.",
                nameof(artifacts));
        }

        Identity = identity;
        AllowedProjectIds = Array.AsReadOnly(projects);
        AllowedSourceRepositories = Array.AsReadOnly(sourceRepositories);
        Artifacts = Array.AsReadOnly(artifactDefinitions);
        AllowedSignerPolicyIds = Array.AsReadOnly(signerPolicies);
        AllowedTimestampPolicyIds = Array.AsReadOnly(timestampPolicies);
        MaximumRequestBytes = maximumRequestBytes;
    }

    public SigningProfileIdentity Identity { get; }

    public ReadOnlyCollection<string> AllowedProjectIds { get; }

    public ReadOnlyCollection<string> AllowedSourceRepositories { get; }

    public ReadOnlyCollection<SigningProfileArtifactDefinition> Artifacts { get; }

    public ReadOnlyCollection<string> AllowedSignerPolicyIds { get; }

    public ReadOnlyCollection<string> AllowedTimestampPolicyIds { get; }

    public long MaximumRequestBytes { get; }

    private static string[] CopyIdentifiers(
        IEnumerable<string> values,
        string parameterName,
        int maximumCount)
    {
        string[] result = values.ToArray();
        if (result.Length is 0 || result.Length > maximumCount)
        {
            throw new ArgumentException(
                $"Identifier collection must contain from one through {maximumCount} values.",
                parameterName);
        }

        if (result.Any(value =>
                value is null
                || !ProfileContractRules.IsSafeIdentifier(value, maximumCharacters: 64)))
        {
            throw new ArgumentException(
                "Identifier collection contains an invalid value.",
                parameterName);
        }

        if (result.Distinct(StringComparer.Ordinal).Count() != result.Length)
        {
            throw new ArgumentException(
                "Identifier collection contains a duplicate value.",
                parameterName);
        }

        return result;
    }

    private static string[] CopySourceRepositories(
        IEnumerable<string> values,
        string parameterName)
    {
        string[] result = values.ToArray();
        if (result.Length is 0 or > 16
            || result.Any(value =>
                value is null
                || !ProfileContractRules.IsSourceRepository(
                    value,
                    maximumSegmentCharacters: 64))
            || result.Distinct(StringComparer.Ordinal).Count() != result.Length)
        {
            throw new ArgumentException(
                "Source repository collection contains an invalid or duplicate value.",
                parameterName);
        }

        return result;
    }
}
