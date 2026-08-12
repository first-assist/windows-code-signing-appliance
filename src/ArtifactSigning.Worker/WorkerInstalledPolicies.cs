using ArtifactSigning.Protocol;

namespace ArtifactSigning.Worker;

public sealed class WorkerAuthorizationPolicy
{
    public WorkerAuthorizationPolicy(
        string projectId,
        string profileId,
        int profileVersion,
        CmsTrustPolicy submitterTrustPolicy,
        CmsTrustPolicy approverTrustPolicy,
        bool requireDistinctSubmitterAndApprover)
    {
        ArgumentNullException.ThrowIfNull(projectId);
        ArgumentNullException.ThrowIfNull(profileId);
        ArgumentNullException.ThrowIfNull(submitterTrustPolicy);
        ArgumentNullException.ThrowIfNull(approverTrustPolicy);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(profileVersion);
        if (!WorkerPolicyRules.IsSafeIdentifier(projectId)
            || !WorkerPolicyRules.IsSafeIdentifier(profileId))
        {
            throw new ArgumentException(
                "Worker authorization identity is invalid.");
        }

        if (requireDistinctSubmitterAndApprover
            && string.Equals(
                submitterTrustPolicy.ExpectedSignerSpkiSha256,
                approverTrustPolicy.ExpectedSignerSpkiSha256,
                StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Dual-control policy requires distinct submitter and approver identities.");
        }

        ProjectId = projectId;
        ProfileId = profileId;
        ProfileVersion = profileVersion;
        SubmitterTrustPolicy = submitterTrustPolicy;
        ApproverTrustPolicy = approverTrustPolicy;
        RequireDistinctSubmitterAndApprover =
            requireDistinctSubmitterAndApprover;
    }

    public string ProjectId { get; }

    public string ProfileId { get; }

    public int ProfileVersion { get; }

    public CmsTrustPolicy SubmitterTrustPolicy { get; }

    public CmsTrustPolicy ApproverTrustPolicy { get; }

    public bool RequireDistinctSubmitterAndApprover { get; }

    internal bool Matches(
        string projectId,
        string profileId,
        int profileVersion)
    {
        return string.Equals(ProjectId, projectId, StringComparison.Ordinal)
            && string.Equals(ProfileId, profileId, StringComparison.Ordinal)
            && ProfileVersion == profileVersion;
    }
}

public sealed class WorkerInstalledSigningPolicy
{
    public WorkerInstalledSigningPolicy(
        string signerPolicyId,
        string timestampPolicyId,
        string signToolSha256,
        string signerThumbprint,
        string signerSpkiSha256,
        IWorkerArtifactSigner artifactSigner)
        : this(
            signerPolicyId,
            timestampPolicyId,
            WorkerSigningProvider.LocalMachineCertificate,
            signToolSha256,
            signerThumbprint,
            signerSpkiSha256,
            artifactSigner)
    {
    }

    public WorkerInstalledSigningPolicy(
        string signerPolicyId,
        string timestampPolicyId,
        WorkerSigningProvider provider,
        string signToolSha256,
        string? signerThumbprint,
        string? signerSpkiSha256,
        IWorkerArtifactSigner artifactSigner)
    {
        ArgumentNullException.ThrowIfNull(signerPolicyId);
        ArgumentNullException.ThrowIfNull(timestampPolicyId);
        ArgumentNullException.ThrowIfNull(signToolSha256);
        ArgumentNullException.ThrowIfNull(artifactSigner);
        if (!WorkerPolicyRules.IsSafeIdentifier(signerPolicyId)
            || !WorkerPolicyRules.IsSafeIdentifier(timestampPolicyId)
            || !WorkerPolicyRules.IsLowerSha256(signToolSha256)
            || !Enum.IsDefined(provider)
            || provider is WorkerSigningProvider.LocalMachineCertificate
                && (!WorkerPolicyRules.IsUpperThumbprint(
                        signerThumbprint ?? string.Empty)
                    || !WorkerPolicyRules.IsLowerSha256(
                        signerSpkiSha256 ?? string.Empty))
            || provider is WorkerSigningProvider.MicrosoftArtifactSigning
                && (signerThumbprint is not null
                    || signerSpkiSha256 is not null))
        {
            throw new ArgumentException(
                "Installed Worker signing policy is invalid.");
        }

        SignerPolicyId = signerPolicyId;
        TimestampPolicyId = timestampPolicyId;
        Provider = provider;
        SignToolSha256 = signToolSha256;
        SignerThumbprint = signerThumbprint;
        SignerSpkiSha256 = signerSpkiSha256;
        ArtifactSigner = artifactSigner;
    }

    public string SignerPolicyId { get; }

    public string TimestampPolicyId { get; }

    public WorkerSigningProvider Provider { get; }

    public string SignToolSha256 { get; }

    public string? SignerThumbprint { get; }

    public string? SignerSpkiSha256 { get; }

    public IWorkerArtifactSigner ArtifactSigner { get; }

    internal bool Matches(
        string signerPolicyId,
        string timestampPolicyId)
    {
        return string.Equals(
                SignerPolicyId,
                signerPolicyId,
                StringComparison.Ordinal)
            && string.Equals(
                TimestampPolicyId,
                timestampPolicyId,
                StringComparison.Ordinal);
    }
}

internal static class WorkerPolicyRules
{
    internal static bool IsSafeIdentifier(string value)
    {
        return value.Length is > 0 and <= 64
            && char.IsAsciiLetterOrDigit(value[0])
            && value.All(character =>
                char.IsAsciiLetterOrDigit(character)
                || character is '-' or '_' or '.');
    }

    internal static bool IsLowerSha256(string value)
    {
        return value.Length is 64
            && value.All(character =>
                character is >= '0' and <= '9'
                    or >= 'a' and <= 'f');
    }

    internal static bool IsUpperThumbprint(string value)
    {
        return value.Length is 40
            && value.All(character =>
                character is >= '0' and <= '9'
                    or >= 'A' and <= 'F');
    }
}
