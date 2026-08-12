using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;
using ArtifactSigning.Protocol;
using ArtifactSigning.Windows;

namespace ArtifactSigning.Gateway;

public enum GatewayDeploymentMode
{
    Production,
    DisposableTest,
    RetainedLab,
}

public sealed record GatewayTrustConfiguration(
    string ExpectedSignerSpkiSha256,
    string RequiredEnhancedKeyUsageOid,
    IReadOnlyList<string> TrustedRootThumbprints,
    IReadOnlyList<string> ExtraCertificateThumbprints,
    CmsRevocationPolicy RevocationPolicy,
    int UrlRetrievalTimeoutSeconds,
    string? ExpectedSignerCertificateSha256 = null);

public sealed record GatewayClientIdentityConfiguration(
    string CertificateSha256,
    string SubjectPublicKeyInfoSha256);

public sealed record GatewayAuthorizationConfiguration(
    string ProjectId,
    string ProfileId,
    int ProfileVersion,
    GatewayClientIdentityConfiguration SubmitterClient,
    GatewayTrustConfiguration SubmitterTrust,
    GatewayClientIdentityConfiguration ApproverClient,
    GatewayTrustConfiguration ApproverTrust,
    bool RequireDistinctSubmitterAndApprover);

public sealed record GatewayAuditorConfiguration(
    string ProjectId,
    string ProfileId,
    int ProfileVersion,
    GatewayClientIdentityConfiguration Client);

public sealed class GatewayServiceConfiguration
{
    public const string FormatIdentifier =
        "ArtifactSigningGatewayConfigurationV2";
    public const string ConfigurationFileName = "gateway.json";
    public const int MaximumConfigurationBytes = 128 * 1024;

    private static readonly JsonSerializerOptions SerializerOptions =
        new()
        {
            AllowDuplicateProperties = false,
            AllowTrailingCommas = false,
            MaxDepth = 16,
            PropertyNameCaseInsensitive = false,
            ReadCommentHandling = JsonCommentHandling.Disallow,
            UnmappedMemberHandling =
                JsonUnmappedMemberHandling.Disallow,
        };
    private static readonly SearchValues<char>
        ServiceSidCharacters =
            SearchValues.Create("0123456789-");

    private GatewayServiceConfiguration(
        GatewayDeploymentMode mode,
        string gatewayServiceSid,
        string workerServiceSid,
        string profileSetSha256,
        IPAddress listenAddress,
        int listenPort,
        string serverCertificateThumbprint,
        IReadOnlyList<GatewayAuthorizationConfiguration>
            authorizationPolicies,
        IReadOnlyList<GatewayAuditorConfiguration> auditors,
        GatewayTrustConfiguration receiptTrust)
    {
        Mode = mode;
        GatewayServiceSid = gatewayServiceSid;
        WorkerServiceSid = workerServiceSid;
        ProfileSetSha256 = profileSetSha256;
        ListenAddress = listenAddress;
        ListenPort = listenPort;
        ServerCertificateThumbprint =
            serverCertificateThumbprint;
        AuthorizationPolicies = authorizationPolicies;
        Auditors = auditors;
        ReceiptTrust = receiptTrust;
    }

    public GatewayDeploymentMode Mode { get; }

    public string GatewayServiceSid { get; }

    public string WorkerServiceSid { get; }

    public string ProfileSetSha256 { get; }

    public IPAddress ListenAddress { get; }

    public int ListenPort { get; }

    public string ServerCertificateThumbprint { get; }

    public IReadOnlyList<GatewayAuthorizationConfiguration>
        AuthorizationPolicies
    { get; }

    public IReadOnlyList<GatewayAuditorConfiguration> Auditors
    {
        get;
    }

    public GatewayTrustConfiguration ReceiptTrust { get; }

    public static string GetInstalledConfigurationPath()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "The installed Gateway configuration is Windows-only.");
        }

        string programFiles = Environment.GetFolderPath(
            Environment.SpecialFolder.ProgramFiles);
        if (string.IsNullOrWhiteSpace(programFiles)
            || !Path.IsPathFullyQualified(programFiles))
        {
            throw new InvalidOperationException(
                "Program Files could not be resolved.");
        }

        return Path.Combine(
            programFiles,
            "ArtifactSigning",
            "Gateway",
            ConfigurationFileName);
    }

    public static GatewayServiceConfiguration LoadInstalled()
    {
        string path = GetInstalledConfigurationPath();
        byte[] before = WindowsDirectFileReader.ReadAllBytes(
            path,
            MaximumConfigurationBytes);
        GatewayServiceConfiguration configuration = Parse(before);
        GatewayInstalledSecurityValidator
            .ValidateConfigurationFile(
                path,
                configuration.GatewayServiceSid,
                configuration.WorkerServiceSid);
        byte[] after = WindowsDirectFileReader.ReadAllBytes(
            path,
            MaximumConfigurationBytes);
        if (!before.AsSpan().SequenceEqual(after))
        {
            throw new InvalidDataException(
                "Gateway configuration changed during validation.");
        }

        return Parse(after);
    }

    public static GatewayServiceConfiguration Parse(
        ReadOnlySpan<byte> json)
    {
        if (json.IsEmpty || json.Length > MaximumConfigurationBytes)
        {
            throw new InvalidDataException(
                "Gateway configuration is empty or oversized.");
        }

        GatewayConfigurationDto dto;
        try
        {
            dto = JsonSerializer.Deserialize<
                    GatewayConfigurationDto>(
                    json,
                    SerializerOptions)
                ?? throw InvalidConfiguration();
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Gateway configuration JSON is invalid.",
                exception);
        }

        return Validate(dto);
    }

    private static GatewayServiceConfiguration Validate(
        GatewayConfigurationDto dto)
    {
        if (!string.Equals(
                dto.Format,
                FormatIdentifier,
                StringComparison.Ordinal)
            || !Enum.TryParse(
                dto.Mode,
                ignoreCase: false,
                out GatewayDeploymentMode mode)
            || !Enum.IsDefined(mode)
            || !string.Equals(dto.Mode, mode.ToString(), StringComparison.Ordinal)
            || !IsServiceSid(dto.GatewayServiceSid)
            || !IsServiceSid(dto.WorkerServiceSid)
            || string.Equals(
                dto.GatewayServiceSid,
                dto.WorkerServiceSid,
                StringComparison.Ordinal)
            || !GatewayContractRules.IsLowerHex(
                dto.ProfileSetSha256,
                64)
            || !IPAddress.TryParse(
                dto.ListenAddress,
                out IPAddress? listenAddress)
            || listenAddress.IsIPv4MappedToIPv6
            || listenAddress.Equals(IPAddress.Any)
            || listenAddress.Equals(IPAddress.IPv6Any)
            || mode is GatewayDeploymentMode.Production
                or GatewayDeploymentMode.RetainedLab
                && !IsPrivateAddress(listenAddress)
            || dto.ListenPort is < 1 or > 65535
            || !IsUpperThumbprint(
                dto.ServerCertificateThumbprint)
            || dto.AuthorizationPolicies is null
                or { Count: 0 or > 32 }
            || dto.Auditors is null
                or { Count: > 32 }
            || dto.ReceiptTrust is null)
        {
            throw InvalidConfiguration();
        }

        GatewayAuthorizationConfiguration[] authorizations =
            dto.AuthorizationPolicies
                .Select(item => ValidateAuthorization(item, mode))
                .ToArray();
        GatewayAuditorConfiguration[] auditors =
            dto.Auditors
                .Select(ValidateAuditor)
                .ToArray();
        GatewayTrustConfiguration receiptTrust =
            ValidateTrust(dto.ReceiptTrust, mode);
        if (authorizations
                .Select(item => (
                    item.ProjectId,
                    item.ProfileId,
                    item.ProfileVersion))
                .Distinct()
                .Count()
            != authorizations.Length
            || auditors
                .Select(item => (
                    item.ProjectId,
                    item.ProfileId,
                    item.ProfileVersion,
                    item.Client.CertificateSha256))
                .Distinct()
                .Count()
            != auditors.Length)
        {
            throw InvalidConfiguration();
        }

        return new GatewayServiceConfiguration(
            mode,
            dto.GatewayServiceSid,
            dto.WorkerServiceSid,
            dto.ProfileSetSha256,
            listenAddress,
            dto.ListenPort,
            dto.ServerCertificateThumbprint,
            Array.AsReadOnly(authorizations),
            Array.AsReadOnly(auditors),
            receiptTrust);
    }

    private static GatewayAuthorizationConfiguration
        ValidateAuthorization(
            GatewayAuthorizationDto dto,
            GatewayDeploymentMode mode)
    {
        if (dto is null
            || !GatewayContractRules.IsSafeIdentifier(
                dto.ProjectId)
            || !GatewayContractRules.IsSafeIdentifier(
                dto.ProfileId)
            || dto.ProfileVersion <= 0
            || dto.SubmitterClient is null
            || dto.SubmitterTrust is null
            || dto.ApproverClient is null
            || dto.ApproverTrust is null)
        {
            throw InvalidConfiguration();
        }

        GatewayClientIdentityConfiguration submitterClient =
            ValidateClient(dto.SubmitterClient);
        GatewayClientIdentityConfiguration approverClient =
            ValidateClient(dto.ApproverClient);
        GatewayTrustConfiguration submitterTrust =
            ValidateTrust(dto.SubmitterTrust, mode);
        GatewayTrustConfiguration approverTrust =
            ValidateTrust(dto.ApproverTrust, mode);
        if (!string.Equals(
                submitterClient.SubjectPublicKeyInfoSha256,
                submitterTrust.ExpectedSignerSpkiSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                approverClient.SubjectPublicKeyInfoSha256,
                approverTrust.ExpectedSignerSpkiSha256,
                StringComparison.Ordinal)
            || mode is GatewayDeploymentMode.RetainedLab
                && (!string.Equals(
                        submitterClient.CertificateSha256,
                        submitterTrust.ExpectedSignerCertificateSha256,
                        StringComparison.Ordinal)
                    || !string.Equals(
                        approverClient.CertificateSha256,
                        approverTrust.ExpectedSignerCertificateSha256,
                        StringComparison.Ordinal))
            || mode is GatewayDeploymentMode.Production
                or GatewayDeploymentMode.RetainedLab
                && (!dto.RequireDistinctSubmitterAndApprover
                    || string.Equals(
                        submitterClient
                            .SubjectPublicKeyInfoSha256,
                        approverClient
                            .SubjectPublicKeyInfoSha256,
                        StringComparison.Ordinal)))
        {
            throw InvalidConfiguration();
        }

        return new GatewayAuthorizationConfiguration(
            dto.ProjectId,
            dto.ProfileId,
            dto.ProfileVersion,
            submitterClient,
            submitterTrust,
            approverClient,
            approverTrust,
            dto.RequireDistinctSubmitterAndApprover);
    }

    private static GatewayAuditorConfiguration ValidateAuditor(
        GatewayAuditorDto dto)
    {
        if (dto is null
            || !GatewayContractRules.IsSafeIdentifier(
                dto.ProjectId)
            || !GatewayContractRules.IsSafeIdentifier(
                dto.ProfileId)
            || dto.ProfileVersion <= 0
            || dto.Client is null)
        {
            throw InvalidConfiguration();
        }

        return new GatewayAuditorConfiguration(
            dto.ProjectId,
            dto.ProfileId,
            dto.ProfileVersion,
            ValidateClient(dto.Client));
    }

    private static GatewayClientIdentityConfiguration
        ValidateClient(GatewayClientIdentityDto dto)
    {
        if (!GatewayContractRules.IsLowerHex(
                dto.CertificateSha256,
                64)
            || !GatewayContractRules.IsLowerHex(
                dto.SubjectPublicKeyInfoSha256,
                64))
        {
            throw InvalidConfiguration();
        }

        return new GatewayClientIdentityConfiguration(
            dto.CertificateSha256,
            dto.SubjectPublicKeyInfoSha256);
    }

    private static GatewayTrustConfiguration ValidateTrust(
        GatewayTrustDto dto,
        GatewayDeploymentMode mode)
    {
        if (!GatewayContractRules.IsLowerHex(
                dto.ExpectedSignerSpkiSha256,
                64)
            || mode is GatewayDeploymentMode.RetainedLab
                && !GatewayContractRules.IsLowerHex(
                    dto.ExpectedSignerCertificateSha256 ?? string.Empty,
                    64)
            || mode is not GatewayDeploymentMode.RetainedLab
                && dto.HasExpectedSignerCertificateSha256
            || !IsCanonicalOid(dto.RequiredEnhancedKeyUsageOid)
            || dto.TrustedRootThumbprints is null
                or { Count: 0 or > CmsTrustPolicy.MaximumTrustedRoots }
            || dto.ExtraCertificateThumbprints is null
                or { Count: > CmsTrustPolicy.MaximumExtraCertificates }
            || dto.TrustedRootThumbprints.Any(
                item => !IsUpperThumbprint(item))
            || dto.ExtraCertificateThumbprints.Any(
                item => !IsUpperThumbprint(item))
            || dto.TrustedRootThumbprints
                    .Distinct(StringComparer.Ordinal)
                    .Count()
                != dto.TrustedRootThumbprints.Count
            || dto.ExtraCertificateThumbprints
                    .Distinct(StringComparer.Ordinal)
                    .Count()
                != dto.ExtraCertificateThumbprints.Count
            || !Enum.TryParse(
                dto.RevocationPolicy,
                ignoreCase: false,
                out CmsRevocationPolicy revocationPolicy)
            || !Enum.IsDefined(revocationPolicy)
            || !string.Equals(
                dto.RevocationPolicy,
                revocationPolicy.ToString(),
                StringComparison.Ordinal)
            || !IsAllowedCmsRevocationPolicy(mode, revocationPolicy)
            || dto.UrlRetrievalTimeoutSeconds is < 1 or > 15)
        {
            throw InvalidConfiguration();
        }

        return new GatewayTrustConfiguration(
            dto.ExpectedSignerSpkiSha256,
            dto.RequiredEnhancedKeyUsageOid,
            Array.AsReadOnly(
                dto.TrustedRootThumbprints.ToArray()),
            Array.AsReadOnly(
                dto.ExtraCertificateThumbprints.ToArray()),
            revocationPolicy,
            dto.UrlRetrievalTimeoutSeconds,
            dto.ExpectedSignerCertificateSha256);
    }

    private static bool IsAllowedCmsRevocationPolicy(
        GatewayDeploymentMode mode,
        CmsRevocationPolicy revocationPolicy)
    {
        return mode switch
        {
            GatewayDeploymentMode.Production =>
                revocationPolicy is CmsRevocationPolicy.Online,
            GatewayDeploymentMode.DisposableTest =>
                revocationPolicy is CmsRevocationPolicy.DisposableTestNoCheck,
            GatewayDeploymentMode.RetainedLab =>
                revocationPolicy is CmsRevocationPolicy.RetainedLabPinned,
            _ => false,
        };
    }

    private static bool IsPrivateAddress(IPAddress address)
    {
        if (address.AddressFamily
            is System.Net.Sockets.AddressFamily.InterNetwork)
        {
            byte[] bytes = address.GetAddressBytes();
            return bytes[0] is 10
                || bytes[0] is 172
                    && bytes[1] is >= 16 and <= 31
                || bytes[0] is 192 && bytes[1] is 168;
        }

        byte[] ipv6 = address.GetAddressBytes();
        return ipv6.Length is 16
            && (ipv6[0] & 0xfe) == 0xfc;
    }

    private static bool IsServiceSid(string value)
    {
        return value.Length is > 0 and <= 184
            && value.StartsWith(
                "S-1-5-80-",
                StringComparison.Ordinal)
            && value.Count(character => character is '-') is 8
            && value.AsSpan(1).ContainsAnyExcept(
                ServiceSidCharacters) is false;
    }

    private static bool IsUpperThumbprint(string value)
    {
        return value.Length is 40
            && value.All(character =>
                character is >= '0' and <= '9'
                    or >= 'A' and <= 'F');
    }

    private static bool IsCanonicalOid(string value)
    {
        if (value.Length is 0 or > 128)
        {
            return false;
        }

        string[] arcs = value.Split('.');
        return arcs.Length >= 2
            && arcs.All(arc =>
                arc.Length > 0
                && (arc.Length is 1 || arc[0] is not '0')
                && arc.All(char.IsAsciiDigit))
            && uint.TryParse(arcs[0], out uint first)
            && first <= 2
            && uint.TryParse(arcs[1], out uint second)
            && (first is 2 || second <= 39);
    }

    private static InvalidDataException InvalidConfiguration()
    {
        return new InvalidDataException(
            "Gateway configuration is invalid.");
    }

    [SuppressMessage(
        "Performance",
        "CA1812:Avoid uninstantiated internal classes",
        Justification =
            "The strict JSON serializer constructs this private DTO through reflection.")]
    private sealed class GatewayConfigurationDto
    {
        public required string Format { get; init; }

        public required string Mode { get; init; }

        public required string GatewayServiceSid { get; init; }

        public required string WorkerServiceSid { get; init; }

        public required string ProfileSetSha256 { get; init; }

        public required string ListenAddress { get; init; }

        public required int ListenPort { get; init; }

        public required string ServerCertificateThumbprint
        {
            get;
            init;
        }

        public required List<GatewayAuthorizationDto>
            AuthorizationPolicies
        { get; init; }

        public required List<GatewayAuditorDto> Auditors
        {
            get;
            init;
        }

        public required GatewayTrustDto ReceiptTrust
        {
            get;
            init;
        }
    }

    [SuppressMessage(
        "Performance",
        "CA1812:Avoid uninstantiated internal classes",
        Justification =
            "The strict JSON serializer constructs this private DTO through reflection.")]
    private sealed class GatewayAuthorizationDto
    {
        public required string ProjectId { get; init; }

        public required string ProfileId { get; init; }

        public required int ProfileVersion { get; init; }

        public required GatewayClientIdentityDto SubmitterClient
        {
            get;
            init;
        }

        public required GatewayTrustDto SubmitterTrust
        {
            get;
            init;
        }

        public required GatewayClientIdentityDto ApproverClient
        {
            get;
            init;
        }

        public required GatewayTrustDto ApproverTrust
        {
            get;
            init;
        }

        public required bool RequireDistinctSubmitterAndApprover
        {
            get;
            init;
        }
    }

    [SuppressMessage(
        "Performance",
        "CA1812:Avoid uninstantiated internal classes",
        Justification =
            "The strict JSON serializer constructs this private DTO through reflection.")]
    private sealed class GatewayAuditorDto
    {
        public required string ProjectId { get; init; }

        public required string ProfileId { get; init; }

        public required int ProfileVersion { get; init; }

        public required GatewayClientIdentityDto Client
        {
            get;
            init;
        }
    }

    [SuppressMessage(
        "Performance",
        "CA1812:Avoid uninstantiated internal classes",
        Justification =
            "The strict JSON serializer constructs this private DTO through reflection.")]
    private sealed class GatewayClientIdentityDto
    {
        public required string CertificateSha256 { get; init; }

        public required string SubjectPublicKeyInfoSha256
        {
            get;
            init;
        }
    }

    [SuppressMessage(
        "Performance",
        "CA1812:Avoid uninstantiated internal classes",
        Justification =
            "The strict JSON serializer constructs this private DTO through reflection.")]
    private sealed class GatewayTrustDto
    {
        public required string ExpectedSignerSpkiSha256
        {
            get;
            init;
        }

        private string? _expectedSignerCertificateSha256;

        public string? ExpectedSignerCertificateSha256
        {
            get => _expectedSignerCertificateSha256;
            init
            {
                _expectedSignerCertificateSha256 = value;
                HasExpectedSignerCertificateSha256 = true;
            }
        }

        [JsonIgnore]
        public bool HasExpectedSignerCertificateSha256 { get; private set; }

        public required string RequiredEnhancedKeyUsageOid
        {
            get;
            init;
        }

        public required List<string> TrustedRootThumbprints
        {
            get;
            init;
        }

        public required List<string> ExtraCertificateThumbprints
        {
            get;
            init;
        }

        public required string RevocationPolicy { get; init; }

        public required int UrlRetrievalTimeoutSeconds
        {
            get;
            init;
        }
    }
}
