using System.Text;

namespace ArtifactSigning.Windows;

public static class MicrosoftArtifactSigningMetadataSerializer
{
    public const int MaximumMetadataBytes = 4096;
    public const int MaximumRoleCharacters = 64;

    private static readonly string[] ExcludedCredentials =
    [
        "EnvironmentCredential",
        "WorkloadIdentityCredential",
        "SharedTokenCacheCredential",
        "VisualStudioCredential",
        "VisualStudioCodeCredential",
        "AzureCliCredential",
        "AzurePowerShellCredential",
        "AzureDeveloperCliCredential",
        "InteractiveBrowserCredential",
    ];

    public static byte[] Serialize(
        MicrosoftArtifactSigningPolicy policy,
        Guid trustedRequestId,
        string trustedArtifactRole)
    {
        ArgumentNullException.ThrowIfNull(policy);
        string correlationId = CreateCorrelationId(
            trustedRequestId,
            trustedArtifactRole);

        string metadata = string.Concat(
            "{\"Endpoint\":\"", policy.Endpoint.AbsoluteUri,
            "\",\"CodeSigningAccountName\":\"", policy.CodeSigningAccountName,
            "\",\"CertificateProfileName\":\"", policy.CertificateProfileName,
            "\",\"CorrelationId\":\"", correlationId,
            "\",\"ExcludeCredentials\":[\"",
            string.Join("\",\"", ExcludedCredentials),
            "\"]}");
        byte[] result = Encoding.UTF8.GetBytes(metadata);
        if (result.Length > MaximumMetadataBytes)
        {
            throw new InvalidOperationException(
                "Canonical Artifact Signing metadata exceeds its maximum size.");
        }

        return result;
    }

    public static string CreateCorrelationId(
        Guid trustedRequestId,
        string trustedArtifactRole)
    {
        if (trustedRequestId == Guid.Empty)
        {
            throw new ArgumentException(
                "Request identifier must not be empty.",
                nameof(trustedRequestId));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(trustedArtifactRole);
        if (!IsSafeRole(trustedArtifactRole))
        {
            throw new ArgumentException(
                "Artifact role must be a bounded safe ASCII identifier.",
                nameof(trustedArtifactRole));
        }

        return string.Concat(
            trustedRequestId.ToString("D"),
            ":",
            trustedArtifactRole);
    }

    private static bool IsSafeRole(string value)
    {
        if (value.Length > MaximumRoleCharacters
            || !(value[0] is >= 'A' and <= 'Z'
                or >= 'a' and <= 'z'))
        {
            return false;
        }

        foreach (char character in value)
        {
            if ((character is >= 'A' and <= 'Z')
                || (character is >= 'a' and <= 'z')
                || char.IsAsciiDigit(character))
            {
                continue;
            }

            return false;
        }

        return true;
    }
}
