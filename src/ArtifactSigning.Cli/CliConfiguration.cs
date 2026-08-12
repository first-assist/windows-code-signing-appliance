using System.Text.Json;
using System.Text.Json.Serialization;
using ArtifactSigning.Protocol;

namespace ArtifactSigning.Cli;

public enum CliDeploymentMode
{
    Production,
    DisposableTest,
    RetainedLab,
}

public enum CliIdentityProvider
{
    PemFiles,
    WindowsCurrentUserStore,
}

public sealed record CliIdentityConfiguration(
    CliIdentityProvider Provider,
    string? CertificatePath,
    string? PrivateKeyPath,
    string? PrivateKeyPasswordFile,
    string? CertificateThumbprint);

public sealed record CliTrustConfiguration(
    string ExpectedSignerSpkiSha256,
    string? ExpectedSignerCertificateSha256,
    string RequiredEnhancedKeyUsageOid,
    IReadOnlyList<string> TrustedRootCertificatePaths,
    IReadOnlyList<string> ExtraCertificatePaths,
    CmsRevocationPolicy RevocationPolicy,
    int UrlRetrievalTimeoutSeconds);

public sealed class CliConfiguration
{
    public const string FormatIdentifier =
        "ArtifactSigningCliConfigurationV1";
    public const int MaximumConfigurationBytes =
        128 * 1024;

    private static readonly JsonSerializerOptions
        SerializerOptions = new()
        {
            AllowDuplicateProperties = false,
            AllowTrailingCommas = false,
            MaxDepth = 16,
            PropertyNameCaseInsensitive = false,
            ReadCommentHandling =
                JsonCommentHandling.Disallow,
            UnmappedMemberHandling =
                JsonUnmappedMemberHandling.Disallow,
            Converters =
            {
                new JsonStringEnumConverter(
                    namingPolicy: null,
                    allowIntegerValues: false),
            },
        };

    private CliConfiguration(
        CliDeploymentMode mode,
        Uri serviceUri,
        string serverCertificateSha256,
        string serverSpkiSha256,
        CliIdentityConfiguration clientIdentity,
        CliTrustConfiguration submitterTrust,
        CliTrustConfiguration receiptTrust)
    {
        Mode = mode;
        ServiceUri = serviceUri;
        ServerCertificateSha256 =
            serverCertificateSha256;
        ServerSpkiSha256 = serverSpkiSha256;
        ClientIdentity = clientIdentity;
        SubmitterTrust = submitterTrust;
        ReceiptTrust = receiptTrust;
    }

    public CliDeploymentMode Mode { get; }

    public Uri ServiceUri { get; }

    public string ServerCertificateSha256 { get; }

    public string ServerSpkiSha256 { get; }

    public CliIdentityConfiguration ClientIdentity
    {
        get;
    }

    public CliTrustConfiguration SubmitterTrust { get; }

    public CliTrustConfiguration ReceiptTrust { get; }

    public static CliConfiguration Load(string path)
    {
        string fullPath = CliFileSecurity
            .RequireAbsolutePath(path);
        CliFileSecurity.RequireOwnerOnlyFile(
            fullPath,
            MaximumConfigurationBytes);
        byte[] before = CliFileSecurity.ReadBounded(
            fullPath,
            MaximumConfigurationBytes);
        CliConfiguration configuration = Parse(before);
        byte[] after = CliFileSecurity.ReadBounded(
            fullPath,
            MaximumConfigurationBytes);
        if (!before.AsSpan().SequenceEqual(after))
        {
            throw new InvalidDataException(
                "Client configuration changed while loading.");
        }

        return configuration;
    }

    public static CliConfiguration Parse(
        ReadOnlySpan<byte> json)
    {
        if (json.IsEmpty
            || json.Length > MaximumConfigurationBytes)
        {
            throw new InvalidDataException(
                "Client configuration is empty or oversized.");
        }

        CliConfigurationDto dto;
        try
        {
            dto = JsonSerializer.Deserialize<
                    CliConfigurationDto>(
                    json,
                    SerializerOptions)
                ?? throw InvalidConfiguration();
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Client configuration JSON is invalid.",
                exception);
        }

        if (!string.Equals(
                dto.Format,
                FormatIdentifier,
                StringComparison.Ordinal)
            || !TryParseExactEnum(
                dto.Mode,
                out CliDeploymentMode mode)
            || !TryParseServiceUri(
                dto.ServiceUri,
                out Uri? serviceUri)
            || serviceUri is null
            || !IsLowerSha256(
                dto.ServerCertificateSha256)
            || !IsLowerSha256(dto.ServerSpkiSha256)
            || dto.ClientIdentity is null
            || dto.SubmitterTrust is null
            || dto.ReceiptTrust is null)
        {
            throw InvalidConfiguration();
        }

        return new CliConfiguration(
            mode,
            serviceUri,
            dto.ServerCertificateSha256,
            dto.ServerSpkiSha256,
            ValidateIdentity(dto.ClientIdentity),
            ValidateTrust(dto.SubmitterTrust, mode),
            ValidateTrust(dto.ReceiptTrust, mode));
    }

    private static CliIdentityConfiguration
        ValidateIdentity(CliIdentityDto dto)
    {
        if (!TryParseExactEnum(
                dto.Provider,
                out CliIdentityProvider provider))
        {
            throw InvalidConfiguration();
        }

        if (provider is CliIdentityProvider.PemFiles)
        {
            if (!IsAbsolutePath(dto.CertificatePath)
                || !IsAbsolutePath(dto.PrivateKeyPath)
                || dto.CertificateThumbprint is not null
                || dto.PrivateKeyPasswordFile is not null
                    && !IsAbsolutePath(
                        dto.PrivateKeyPasswordFile))
            {
                throw InvalidConfiguration();
            }
        }
        else if (!OperatingSystem.IsWindows()
            || !IsUpperThumbprint(
                dto.CertificateThumbprint)
            || dto.CertificatePath is not null
            || dto.PrivateKeyPath is not null
            || dto.PrivateKeyPasswordFile is not null)
        {
            throw InvalidConfiguration();
        }

        return new CliIdentityConfiguration(
            provider,
            dto.CertificatePath,
            dto.PrivateKeyPath,
            dto.PrivateKeyPasswordFile,
            dto.CertificateThumbprint);
    }

    private static CliTrustConfiguration ValidateTrust(
        CliTrustDto dto,
        CliDeploymentMode mode)
    {
        if (!IsLowerSha256(
                dto.ExpectedSignerSpkiSha256)
            || !IsOid(dto.RequiredEnhancedKeyUsageOid)
            || dto.TrustedRootCertificatePaths is null
                or
            {
                Count: 0 or >
                    CmsTrustPolicy.MaximumTrustedRoots
            }
            || dto.ExtraCertificatePaths is null
                or
            {
                Count: >
                    CmsTrustPolicy
                        .MaximumExtraCertificates
            }
            || !TryParseExactEnum(
                dto.RevocationPolicy,
                out CmsRevocationPolicy revocationPolicy)
            || !HasAllowedRevocationPolicy(
                mode,
                revocationPolicy,
                dto.ExpectedSignerCertificateSha256)
            || dto.UrlRetrievalTimeoutSeconds is < 1
                or > 15)
        {
            throw InvalidConfiguration();
        }

        string[] roots = ValidateCertificatePaths(
            dto.TrustedRootCertificatePaths);
        string[] extra = ValidateCertificatePaths(
            dto.ExtraCertificatePaths);
        if (roots.Concat(extra)
                .Distinct(StringComparer.Ordinal)
                .Count()
            != roots.Length + extra.Length)
        {
            throw InvalidConfiguration();
        }

        return new CliTrustConfiguration(
            dto.ExpectedSignerSpkiSha256,
            dto.ExpectedSignerCertificateSha256,
            dto.RequiredEnhancedKeyUsageOid,
            Array.AsReadOnly(roots),
            Array.AsReadOnly(extra),
            revocationPolicy,
            dto.UrlRetrievalTimeoutSeconds);
    }

    private static bool HasAllowedRevocationPolicy(
        CliDeploymentMode mode,
        CmsRevocationPolicy revocationPolicy,
        string? expectedSignerCertificateSha256)
    {
        return mode switch
        {
            CliDeploymentMode.Production =>
                revocationPolicy is CmsRevocationPolicy.Online
                && expectedSignerCertificateSha256 is null,
            CliDeploymentMode.DisposableTest =>
                revocationPolicy is CmsRevocationPolicy.DisposableTestNoCheck
                && expectedSignerCertificateSha256 is null,
            CliDeploymentMode.RetainedLab =>
                revocationPolicy is CmsRevocationPolicy.RetainedLabPinned
                && IsLowerSha256(expectedSignerCertificateSha256 ?? string.Empty),
            _ => false,
        };
    }

    private static string[] ValidateCertificatePaths(
        IReadOnlyList<string> paths)
    {
        string[] validated = paths
            .Select(CliFileSecurity.RequireAbsolutePath)
            .ToArray();
        if (validated.Distinct(StringComparer.Ordinal)
                .Count()
            != validated.Length)
        {
            throw InvalidConfiguration();
        }

        return validated;
    }

    private static bool TryParseServiceUri(
        string value,
        out Uri? serviceUri)
    {
        serviceUri = null;
        if (!Uri.TryCreate(
                value,
                UriKind.Absolute,
                out Uri? parsed)
            || !string.Equals(
                parsed.Scheme,
                Uri.UriSchemeHttps,
                StringComparison.Ordinal)
            || parsed.HostNameType is UriHostNameType.Unknown
            || !string.IsNullOrEmpty(parsed.UserInfo)
            || !string.IsNullOrEmpty(parsed.Query)
            || !string.IsNullOrEmpty(parsed.Fragment)
            || parsed.AbsolutePath is not "/")
        {
            return false;
        }

        serviceUri = parsed;
        return true;
    }

    private static bool TryParseExactEnum<TEnum>(
        string value,
        out TEnum parsed)
        where TEnum : struct, Enum
    {
        return Enum.TryParse(
                value,
                ignoreCase: false,
                out parsed)
            && Enum.IsDefined(parsed)
            && string.Equals(
                value,
                parsed.ToString(),
                StringComparison.Ordinal);
    }

    private static bool IsAbsolutePath(string? value)
    {
        return value is not null
            && Path.IsPathFullyQualified(value)
            && value.Length <= 1024;
    }

    private static bool IsLowerSha256(string value)
    {
        return value.Length is 64
            && value.All(character =>
                character is >= '0' and <= '9'
                    or >= 'a' and <= 'f');
    }

    private static bool IsUpperThumbprint(string? value)
    {
        return value is { Length: 40 }
            && value.All(character =>
                character is >= '0' and <= '9'
                    or >= 'A' and <= 'F');
    }

    private static bool IsOid(string value)
    {
        return value.Length is > 2 and <= 128
            && value[0] is >= '0' and <= '2'
            && value[^1] is >= '0' and <= '9'
            && value.Split('.').All(segment =>
                segment.Length > 0
                && (segment.Length is 1
                    || segment[0] is not '0')
                && segment.All(char.IsAsciiDigit));
    }

    private static InvalidDataException
        InvalidConfiguration()
    {
        return new InvalidDataException(
            "Client configuration is invalid.");
    }

    [JsonUnmappedMemberHandling(
        JsonUnmappedMemberHandling.Disallow)]
    private sealed record CliConfigurationDto(
        string Format,
        string Mode,
        string ServiceUri,
        string ServerCertificateSha256,
        string ServerSpkiSha256,
        CliIdentityDto ClientIdentity,
        CliTrustDto SubmitterTrust,
        CliTrustDto ReceiptTrust);

    [JsonUnmappedMemberHandling(
        JsonUnmappedMemberHandling.Disallow)]
    private sealed record CliIdentityDto(
        string Provider,
        string? CertificatePath,
        string? PrivateKeyPath,
        string? PrivateKeyPasswordFile,
        string? CertificateThumbprint);

    [JsonUnmappedMemberHandling(
        JsonUnmappedMemberHandling.Disallow)]
    private sealed record CliTrustDto(
        string ExpectedSignerSpkiSha256,
        string? ExpectedSignerCertificateSha256,
        string RequiredEnhancedKeyUsageOid,
        IReadOnlyList<string>
            TrustedRootCertificatePaths,
        IReadOnlyList<string> ExtraCertificatePaths,
        string RevocationPolicy,
        int UrlRetrievalTimeoutSeconds);
}
