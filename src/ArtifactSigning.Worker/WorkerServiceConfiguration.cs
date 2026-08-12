using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using ArtifactSigning.Protocol;
using ArtifactSigning.Windows;

namespace ArtifactSigning.Worker;

public enum WorkerDeploymentMode
{
    Production,
    DisposableTest,
    RetainedLab,
}

public sealed record WorkerTrustConfiguration(
    string ExpectedSignerSpkiSha256,
    string RequiredEnhancedKeyUsageOid,
    IReadOnlyList<string> TrustedRootThumbprints,
    IReadOnlyList<string> ExtraCertificateThumbprints,
    CmsRevocationPolicy RevocationPolicy,
    int UrlRetrievalTimeoutSeconds,
    string? ExpectedSignerCertificateSha256 = null);

public sealed record WorkerAuthorizationConfiguration(
    string ProjectId,
    string ProfileId,
    int ProfileVersion,
    WorkerTrustConfiguration SubmitterTrust,
    WorkerTrustConfiguration ApproverTrust,
    bool RequireDistinctSubmitterAndApprover);

public enum WorkerSigningProvider
{
    LocalMachineCertificate,
    MicrosoftArtifactSigning,
}

public abstract record WorkerSigningProviderConfiguration;

public sealed record WorkerLocalMachineCertificateSigningConfiguration(
    string SignToolPath,
    string SignToolSha256,
    Version SignToolFileVersion,
    string SignerCertificateThumbprint,
    string? SignerCertificateSha256,
    string? SignerSubjectPublicKeyInfoSha256,
    Uri TimestampUrl,
    int SignToolTimeoutSeconds,
    WindowsTrustRevocationPolicy AuthenticodeRevocationPolicy) :
    WorkerSigningProviderConfiguration;

public sealed record WorkerMicrosoftArtifactSigningConfiguration(
    MicrosoftArtifactSigningRegion Region,
    string CodeSigningAccountName,
    string CertificateProfileName,
    string SignToolPath,
    string SignToolSha256,
    Version SignToolFileVersion,
    string DlibPath,
    string DlibSha256,
    Version DlibFileVersion,
    string ClientToolsInventorySha256,
    string ExpectedPublisherSubjectNameSha256,
    string RequiredPublisherEnhancedKeyUsageOid,
    IReadOnlyList<string> TrustedPublisherRootThumbprints,
    int SignToolTimeoutSeconds,
    WindowsTrustRevocationPolicy AuthenticodeRevocationPolicy) :
    WorkerSigningProviderConfiguration;

public sealed record WorkerSigningConfiguration(
    string SignerPolicyId,
    string TimestampPolicyId,
    WorkerSigningProviderConfiguration ProviderConfiguration)
{
    public WorkerSigningProvider Provider => ProviderConfiguration switch
    {
        WorkerLocalMachineCertificateSigningConfiguration =>
            WorkerSigningProvider.LocalMachineCertificate,
        WorkerMicrosoftArtifactSigningConfiguration =>
            WorkerSigningProvider.MicrosoftArtifactSigning,
        _ => throw new InvalidOperationException(
            "Worker signing provider is not supported."),
    };
}

public sealed record WorkerReceiptConfiguration(
    string CertificateThumbprint,
    WorkerTrustConfiguration Trust);

public sealed class WorkerServiceConfiguration
{
    private const string MicrosoftPublicTrustEkuPrefix =
        "1.3.6.1.4.1.311.97.";
    private const string MicrosoftPublicTrustReservedEkuPrefix =
        "1.3.6.1.4.1.311.97.1.";
    private const string MicrosoftPublicTrustTestEkuPrefix =
        "1.3.6.1.4.1.311.97.1.2.";

    public const string FormatIdentifier =
        "ArtifactSigningWorkerConfigurationV3";
    public const string LegacyFormatIdentifier =
        "ArtifactSigningWorkerConfigurationV2";
    public const string ConfigurationFileName = "worker.json";
    public const int MaximumConfigurationBytes = 64 * 1024;

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        AllowDuplicateProperties = false,
        AllowTrailingCommas = false,
        MaxDepth = 16,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private WorkerServiceConfiguration(
        WorkerDeploymentMode mode,
        string workerServiceSid,
        string gatewayServiceSid,
        string profileSetSha256,
        IReadOnlyList<WorkerAuthorizationConfiguration>
            authorizationPolicies,
        IReadOnlyList<WorkerSigningConfiguration> signingPolicies,
        WorkerReceiptConfiguration receipt)
    {
        Mode = mode;
        WorkerServiceSid = workerServiceSid;
        GatewayServiceSid = gatewayServiceSid;
        ProfileSetSha256 = profileSetSha256;
        AuthorizationPolicies = authorizationPolicies;
        SigningPolicies = signingPolicies;
        Receipt = receipt;
    }

    public WorkerDeploymentMode Mode { get; }

    public string WorkerServiceSid { get; }

    public string GatewayServiceSid { get; }

    public string ProfileSetSha256 { get; }

    public IReadOnlyList<WorkerAuthorizationConfiguration>
        AuthorizationPolicies
    { get; }

    public IReadOnlyList<WorkerSigningConfiguration> SigningPolicies
    {
        get;
    }

    public WorkerReceiptConfiguration Receipt { get; }

    public static string GetInstalledConfigurationPath()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "The installed Worker configuration is Windows-only.");
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
            "Worker",
            ConfigurationFileName);
    }

    public static WorkerServiceConfiguration LoadInstalled()
    {
        string path = GetInstalledConfigurationPath();
        byte[] before = WindowsDirectFileReader.ReadAllBytes(
            path,
            MaximumConfigurationBytes);
        WorkerServiceConfiguration configuration = Parse(before);
        SecurityIdentifier workerSid =
            new(configuration.WorkerServiceSid);
        SecurityIdentifier gatewaySid =
            new(configuration.GatewayServiceSid);
        WorkerInstalledSecurityValidator.ValidateConfigurationFile(
            path,
            workerSid,
            gatewaySid);
        byte[] after = WindowsDirectFileReader.ReadAllBytes(
            path,
            MaximumConfigurationBytes);
        if (!before.AsSpan().SequenceEqual(after))
        {
            throw new InvalidDataException(
                "Worker configuration changed during validation.");
        }

        return Parse(after);
    }

    public static WorkerServiceConfiguration Parse(
        ReadOnlySpan<byte> json)
    {
        if (json.IsEmpty || json.Length > MaximumConfigurationBytes)
        {
            throw new InvalidDataException(
                "Worker configuration is empty or oversized.");
        }

        WorkerConfigurationDto dto;
        try
        {
            dto = JsonSerializer.Deserialize<WorkerConfigurationDto>(
                    json,
                    SerializerOptions)
                ?? throw new InvalidDataException(
                    "Worker configuration is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Worker configuration JSON is invalid.",
                exception);
        }

        return Validate(dto);
    }

    private static WorkerServiceConfiguration Validate(
        WorkerConfigurationDto dto)
    {
        bool isLegacyFormat = string.Equals(
            dto.Format,
            LegacyFormatIdentifier,
            StringComparison.Ordinal);
        if (!isLegacyFormat
                && !string.Equals(
                    dto.Format,
                    FormatIdentifier,
                    StringComparison.Ordinal)
            || !Enum.TryParse(
                dto.Mode,
                ignoreCase: false,
                out WorkerDeploymentMode mode)
            || !Enum.IsDefined(mode)
            || !string.Equals(dto.Mode, mode.ToString(), StringComparison.Ordinal)
            || !IsServiceSid(dto.WorkerServiceSid)
            || !IsServiceSid(dto.GatewayServiceSid)
            || string.Equals(
                dto.WorkerServiceSid,
                dto.GatewayServiceSid,
                StringComparison.Ordinal)
            || !WorkerPolicyRules.IsLowerSha256(
                dto.ProfileSetSha256)
            || dto.AuthorizationPolicies is null
                or { Count: 0 or > 32 }
            || dto.SigningPolicies is null
                or { Count: 0 or > 16 }
            || dto.Receipt is null)
        {
            throw InvalidConfiguration();
        }

        WorkerAuthorizationConfiguration[] authorizations =
            dto.AuthorizationPolicies
                .Select(item => ValidateAuthorization(item, mode))
                .ToArray();
        WorkerSigningConfiguration[] signingPolicies =
            dto.SigningPolicies
                .Select(item => ValidateSigning(
                    item,
                    mode,
                    isLegacyFormat))
                .ToArray();
        WorkerReceiptConfiguration receipt =
            ValidateReceipt(dto.Receipt, mode);

        if (authorizations
                .Select(item => (
                    item.ProjectId,
                    item.ProfileId,
                    item.ProfileVersion,
                    item.SubmitterTrust.ExpectedSignerSpkiSha256,
                    item.ApproverTrust.ExpectedSignerSpkiSha256))
                .Distinct()
                .Count()
            != authorizations.Length
            || signingPolicies
                .Select(item => (
                    item.SignerPolicyId,
                    item.TimestampPolicyId))
                .Distinct()
                .Count()
            != signingPolicies.Length)
        {
            throw InvalidConfiguration();
        }

        return new WorkerServiceConfiguration(
            mode,
            dto.WorkerServiceSid,
            dto.GatewayServiceSid,
            dto.ProfileSetSha256,
            Array.AsReadOnly(authorizations),
            Array.AsReadOnly(signingPolicies),
            receipt);
    }

    private static WorkerAuthorizationConfiguration
        ValidateAuthorization(
            WorkerAuthorizationDto dto,
            WorkerDeploymentMode mode)
    {
        if (dto is null
            || !WorkerPolicyRules.IsSafeIdentifier(dto.ProjectId)
            || !WorkerPolicyRules.IsSafeIdentifier(dto.ProfileId)
            || dto.ProfileVersion <= 0
            || dto.SubmitterTrust is null
            || dto.ApproverTrust is null)
        {
            throw InvalidConfiguration();
        }

        WorkerTrustConfiguration submitter =
            ValidateTrust(dto.SubmitterTrust, mode);
        WorkerTrustConfiguration approver =
            ValidateTrust(dto.ApproverTrust, mode);
        if (mode is WorkerDeploymentMode.Production
            or WorkerDeploymentMode.RetainedLab
            && (!dto.RequireDistinctSubmitterAndApprover
                || string.Equals(
                    submitter.ExpectedSignerSpkiSha256,
                    approver.ExpectedSignerSpkiSha256,
                    StringComparison.Ordinal)))
        {
            throw InvalidConfiguration();
        }

        return new WorkerAuthorizationConfiguration(
            dto.ProjectId,
            dto.ProfileId,
            dto.ProfileVersion,
            submitter,
            approver,
            dto.RequireDistinctSubmitterAndApprover);
    }

    private static WorkerSigningConfiguration ValidateSigning(
        WorkerSigningDto dto,
        WorkerDeploymentMode mode,
        bool isLegacyFormat)
    {
        if (dto is null
            || !WorkerPolicyRules.IsSafeIdentifier(dto.SignerPolicyId)
            || !WorkerPolicyRules.IsSafeIdentifier(dto.TimestampPolicyId))
        {
            throw InvalidConfiguration();
        }

        if (isLegacyFormat)
        {
            if (dto.HasProvider
                || dto.HasLocalMachineCertificate
                || dto.HasMicrosoftArtifactSigning)
            {
                throw InvalidConfiguration();
            }

            return new WorkerSigningConfiguration(
                dto.SignerPolicyId,
                dto.TimestampPolicyId,
                ValidateLocalMachineSigning(dto, mode));
        }

        if (!dto.HasProvider
            || !Enum.TryParse(
                dto.Provider,
                ignoreCase: false,
                out WorkerSigningProvider provider)
            || !Enum.IsDefined(provider)
            || !string.Equals(
                dto.Provider,
                provider.ToString(),
                StringComparison.Ordinal)
            || HasLegacySigningProperties(dto))
        {
            throw InvalidConfiguration();
        }

        WorkerSigningProviderConfiguration providerConfiguration = provider switch
        {
            WorkerSigningProvider.LocalMachineCertificate
                when dto.HasLocalMachineCertificate
                    && !dto.HasMicrosoftArtifactSigning =>
                ValidateLocalMachineSigning(
                    dto.LocalMachineCertificate!,
                    mode),
            WorkerSigningProvider.MicrosoftArtifactSigning
                when dto.HasMicrosoftArtifactSigning
                    && !dto.HasLocalMachineCertificate =>
                ValidateMicrosoftArtifactSigning(
                    dto.MicrosoftArtifactSigning!,
                    mode),
            _ => throw InvalidConfiguration(),
        };

        return new WorkerSigningConfiguration(
            dto.SignerPolicyId,
            dto.TimestampPolicyId,
            providerConfiguration);
    }

    private static WorkerLocalMachineCertificateSigningConfiguration
        ValidateLocalMachineSigning(
            IWorkerLocalMachineSigningDto dto,
            WorkerDeploymentMode mode)
    {
        if (!IsAbsoluteWindowsSignToolPath(dto.SignToolPath)
            || !WorkerPolicyRules.IsLowerSha256(dto.SignToolSha256)
            || !TryParseFourPartVersion(
                dto.SignToolFileVersion,
                out Version? version)
            || !WorkerPolicyRules.IsUpperThumbprint(
                dto.SignerCertificateThumbprint)
            || mode is WorkerDeploymentMode.RetainedLab
                && (!WorkerPolicyRules.IsLowerSha256(
                        dto.SignerCertificateSha256 ?? string.Empty)
                    || !WorkerPolicyRules.IsLowerSha256(
                        dto.SignerSubjectPublicKeyInfoSha256 ?? string.Empty))
            || mode is not WorkerDeploymentMode.RetainedLab
                && (dto.HasSignerCertificateSha256
                    || dto.HasSignerSubjectPublicKeyInfoSha256)
            || !Uri.TryCreate(
                dto.TimestampUrl,
                UriKind.Absolute,
                out Uri? timestampUrl)
            || !IsBoundedTimestampUrl(timestampUrl)
            || !TryParseAuthenticodePolicy(
                dto.SignToolTimeoutSeconds,
                dto.AuthenticodeRevocationPolicy,
                mode,
                out WindowsTrustRevocationPolicy revocationPolicy))
        {
            throw InvalidConfiguration();
        }

        return new WorkerLocalMachineCertificateSigningConfiguration(
            dto.SignToolPath,
            dto.SignToolSha256,
            version!,
            dto.SignerCertificateThumbprint,
            dto.SignerCertificateSha256,
            dto.SignerSubjectPublicKeyInfoSha256,
            timestampUrl,
            dto.SignToolTimeoutSeconds,
            revocationPolicy);
    }

    private static WorkerMicrosoftArtifactSigningConfiguration
        ValidateMicrosoftArtifactSigning(
            WorkerMicrosoftArtifactSigningDto dto,
            WorkerDeploymentMode mode)
    {
        if (mode is WorkerDeploymentMode.RetainedLab
            || !Enum.TryParse(
                dto.Region,
                ignoreCase: false,
                out MicrosoftArtifactSigningRegion region)
            || !Enum.IsDefined(region)
            || !string.Equals(
                dto.Region,
                region.ToString(),
                StringComparison.Ordinal)
            || !IsAbsoluteWindowsSignToolPath(dto.SignToolPath)
            || !WorkerPolicyRules.IsLowerSha256(dto.SignToolSha256)
            || !TryParseFourPartVersion(
                dto.SignToolFileVersion,
                out Version? signToolVersion)
            || !IsAbsoluteWindowsDlibPath(dto.DlibPath)
            || !WorkerPolicyRules.IsLowerSha256(dto.DlibSha256)
            || !TryParseFourPartVersion(
                dto.DlibFileVersion,
                out Version? dlibVersion)
            || !WorkerPolicyRules.IsLowerSha256(
                dto.ClientToolsInventorySha256)
            || !WorkerPolicyRules.IsLowerSha256(
                dto.ExpectedPublisherSubjectNameSha256)
            || !IsCanonicalOid(dto.RequiredPublisherEnhancedKeyUsageOid)
            || !IsAllowedMicrosoftSubscriberEku(
                mode,
                dto.RequiredPublisherEnhancedKeyUsageOid)
            || dto.TrustedPublisherRootThumbprints is null
                or { Count: 0 or > 8 }
            || !AllUniqueUpperThumbprints(
                dto.TrustedPublisherRootThumbprints)
            || !TryParseAuthenticodePolicy(
                dto.SignToolTimeoutSeconds,
                dto.AuthenticodeRevocationPolicy,
                mode,
                out WindowsTrustRevocationPolicy revocationPolicy))
        {
            throw InvalidConfiguration();
        }

        try
        {
            _ = new MicrosoftArtifactSigningPolicy(
                region,
                dto.CodeSigningAccountName,
                dto.CertificateProfileName,
                dto.SignToolPath,
                dto.SignToolSha256,
                signToolVersion!,
                dto.DlibPath,
                dto.DlibSha256,
                dlibVersion!,
                dto.ClientToolsInventorySha256,
                TimeSpan.FromSeconds(dto.SignToolTimeoutSeconds));
            _ = AuthenticodeTrustPolicy
                .CreateMicrosoftArtifactSigningPublisher(
                    dto.ExpectedPublisherSubjectNameSha256,
                    dto.RequiredPublisherEnhancedKeyUsageOid,
                    dto.TrustedPublisherRootThumbprints,
                    revocationPolicy,
                    revocationPolicy);
        }
        catch (ArgumentException)
        {
            throw InvalidConfiguration();
        }

        return new WorkerMicrosoftArtifactSigningConfiguration(
            region,
            dto.CodeSigningAccountName,
            dto.CertificateProfileName,
            dto.SignToolPath,
            dto.SignToolSha256,
            signToolVersion!,
            dto.DlibPath,
            dto.DlibSha256,
            dlibVersion!,
            dto.ClientToolsInventorySha256,
            dto.ExpectedPublisherSubjectNameSha256,
            dto.RequiredPublisherEnhancedKeyUsageOid,
            Array.AsReadOnly(
                dto.TrustedPublisherRootThumbprints.ToArray()),
            dto.SignToolTimeoutSeconds,
            revocationPolicy);
    }

    private static bool TryParseAuthenticodePolicy(
        int timeoutSeconds,
        string revocationPolicyValue,
        WorkerDeploymentMode mode,
        out WindowsTrustRevocationPolicy revocationPolicy)
    {
        revocationPolicy = default;
        return timeoutSeconds is >= 1 and <= 120
            && Enum.TryParse(
                revocationPolicyValue,
                ignoreCase: false,
                out revocationPolicy)
            && Enum.IsDefined(revocationPolicy)
            && string.Equals(
                revocationPolicyValue,
                revocationPolicy.ToString(),
                StringComparison.Ordinal)
            && IsAllowedAuthenticodeRevocationPolicy(
                mode,
                revocationPolicy);
    }

    private static bool IsAllowedMicrosoftSubscriberEku(
        WorkerDeploymentMode mode,
        string value)
    {
        return mode switch
        {
            WorkerDeploymentMode.Production =>
                value.StartsWith(
                    MicrosoftPublicTrustEkuPrefix,
                    StringComparison.Ordinal)
                && !value.StartsWith(
                    MicrosoftPublicTrustReservedEkuPrefix,
                    StringComparison.Ordinal),
            WorkerDeploymentMode.DisposableTest =>
                value.StartsWith(
                    MicrosoftPublicTrustTestEkuPrefix,
                    StringComparison.Ordinal),
            _ => false,
        };
    }

    private static bool TryParseFourPartVersion(
        string value,
        out Version? version)
    {
        return Version.TryParse(value, out version)
            && version.Revision >= 0
            && string.Equals(
                version.ToString(),
                value,
                StringComparison.Ordinal);
    }

    private static WorkerReceiptConfiguration ValidateReceipt(
        WorkerReceiptDto dto,
        WorkerDeploymentMode mode)
    {
        if (!WorkerPolicyRules.IsUpperThumbprint(
                dto.CertificateThumbprint)
            || dto.Trust is null)
        {
            throw InvalidConfiguration();
        }

        return new WorkerReceiptConfiguration(
            dto.CertificateThumbprint,
            ValidateTrust(dto.Trust, mode));
    }

    private static WorkerTrustConfiguration ValidateTrust(
        WorkerTrustDto dto,
        WorkerDeploymentMode mode)
    {
        if (!WorkerPolicyRules.IsLowerSha256(
                dto.ExpectedSignerSpkiSha256)
            || mode is WorkerDeploymentMode.RetainedLab
                && !WorkerPolicyRules.IsLowerSha256(
                    dto.ExpectedSignerCertificateSha256 ?? string.Empty)
            || mode is not WorkerDeploymentMode.RetainedLab
                && dto.HasExpectedSignerCertificateSha256
            || !IsCanonicalOid(dto.RequiredEnhancedKeyUsageOid)
            || dto.TrustedRootThumbprints is null
                or { Count: 0 or > CmsTrustPolicy.MaximumTrustedRoots }
            || dto.ExtraCertificateThumbprints is null
                or
            {
                Count: >
                        CmsTrustPolicy.MaximumExtraCertificates,
            }
            || !AllUniqueUpperThumbprints(
                dto.TrustedRootThumbprints)
            || !AllUniqueUpperThumbprints(
                dto.ExtraCertificateThumbprints)
            || dto.TrustedRootThumbprints.Intersect(
                    dto.ExtraCertificateThumbprints,
                    StringComparer.Ordinal)
                .Any()
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

        return new WorkerTrustConfiguration(
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
        WorkerDeploymentMode mode,
        CmsRevocationPolicy revocationPolicy)
    {
        return mode switch
        {
            WorkerDeploymentMode.Production =>
                revocationPolicy is CmsRevocationPolicy.Online,
            WorkerDeploymentMode.DisposableTest =>
                revocationPolicy is CmsRevocationPolicy.DisposableTestNoCheck,
            WorkerDeploymentMode.RetainedLab =>
                revocationPolicy is CmsRevocationPolicy.RetainedLabPinned,
            _ => false,
        };
    }

    private static bool IsAllowedAuthenticodeRevocationPolicy(
        WorkerDeploymentMode mode,
        WindowsTrustRevocationPolicy revocationPolicy)
    {
        return mode switch
        {
            WorkerDeploymentMode.Production =>
                revocationPolicy is WindowsTrustRevocationPolicy.Online,
            WorkerDeploymentMode.DisposableTest =>
                revocationPolicy is WindowsTrustRevocationPolicy.DisposableTestNoCheck,
            WorkerDeploymentMode.RetainedLab =>
                revocationPolicy is WindowsTrustRevocationPolicy.RetainedLabPinned,
            _ => false,
        };
    }

    private static bool AllUniqueUpperThumbprints(
        List<string> thumbprints)
    {
        return thumbprints.All(WorkerPolicyRules.IsUpperThumbprint)
            && thumbprints.Distinct(StringComparer.Ordinal).Count()
                == thumbprints.Count;
    }

    private static bool IsCanonicalOid(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 128)
        {
            return false;
        }

        string[] arcs = value.Split('.');
        if (arcs.Length < 2
            || arcs.Any(arc =>
                arc.Length is 0
                || arc.Length > 1 && arc[0] is '0'
                || !arc.All(char.IsAsciiDigit))
            || !uint.TryParse(arcs[0], out uint first)
            || !uint.TryParse(arcs[1], out uint second)
            || first > 2
            || first < 2 && second > 39)
        {
            return false;
        }

        return true;
    }

    private static bool IsServiceSid(string value)
    {
        if (string.IsNullOrWhiteSpace(value)
            || !value.StartsWith("S-1-5-80-", StringComparison.Ordinal))
        {
            return false;
        }

        string[] segments = value.Split('-');
        return segments.Length is 9
            && segments.Skip(4).All(segment =>
                uint.TryParse(segment, out _));
    }

    private static bool IsAbsoluteWindowsSignToolPath(string value)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length > 260
            || value.Length < 4
            || !char.IsAsciiLetter(value[0])
            || value[1] is not ':'
            || value[2] is not '\\'
            || value.Contains('/', StringComparison.Ordinal)
            || value.Split('\\').Any(segment =>
                segment is "." or "..")
            || !string.Equals(
                value[(value.LastIndexOf('\\') + 1)..],
                "signtool.exe",
                StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return true;
    }

    private static bool IsAbsoluteWindowsDlibPath(string value)
    {
        return !string.IsNullOrWhiteSpace(value)
            && value.Length <= 260
            && value.Length >= 4
            && char.IsAsciiLetter(value[0])
            && value[1] is ':'
            && value[2] is '\\'
            && !value.Contains('/', StringComparison.Ordinal)
            && !value.Split('\\').Any(segment => segment is "." or "..")
            && string.Equals(
                value[(value.LastIndexOf('\\') + 1)..],
                "Azure.CodeSigning.Dlib.dll",
                StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasLegacySigningProperties(WorkerSigningDto dto)
    {
        return dto.HasSignToolPath
            || dto.HasSignToolSha256
            || dto.HasSignToolFileVersion
            || dto.HasSignerCertificateThumbprint
            || dto.HasSignerCertificateSha256
            || dto.HasSignerSubjectPublicKeyInfoSha256
            || dto.HasTimestampUrl
            || dto.HasSignToolTimeoutSeconds
            || dto.HasAuthenticodeRevocationPolicy;
    }

    private static bool IsBoundedTimestampUrl(Uri value)
    {
        return value.AbsoluteUri.Length <=
                InstalledSignToolPolicy.MaximumTimestampUrlCharacters
            && value.Scheme is "https" or "http"
            && !string.IsNullOrWhiteSpace(value.Host)
            && string.IsNullOrEmpty(value.UserInfo)
            && string.IsNullOrEmpty(value.Query)
            && string.IsNullOrEmpty(value.Fragment);
    }

    private static InvalidDataException InvalidConfiguration()
    {
        return new InvalidDataException(
            "Worker configuration values are invalid.");
    }

    private sealed class WorkerConfigurationDto
    {
        public required string Format { get; init; }

        public required string Mode { get; init; }

        public required string WorkerServiceSid { get; init; }

        public required string GatewayServiceSid { get; init; }

        public required string ProfileSetSha256 { get; init; }

        public required List<WorkerAuthorizationDto>
            AuthorizationPolicies
        { get; init; }

        public required List<WorkerSigningDto> SigningPolicies
        {
            get;
            init;
        }

        public required WorkerReceiptDto Receipt { get; init; }
    }

    private sealed class WorkerAuthorizationDto
    {
        public required string ProjectId { get; init; }

        public required string ProfileId { get; init; }

        public required int ProfileVersion { get; init; }

        public required WorkerTrustDto SubmitterTrust { get; init; }

        public required WorkerTrustDto ApproverTrust { get; init; }

        public required bool RequireDistinctSubmitterAndApprover
        {
            get;
            init;
        }
    }

    private interface IWorkerLocalMachineSigningDto
    {
        string SignToolPath { get; }

        string SignToolSha256 { get; }

        string SignToolFileVersion { get; }

        string SignerCertificateThumbprint { get; }

        string? SignerCertificateSha256 { get; }

        bool HasSignerCertificateSha256 { get; }

        string? SignerSubjectPublicKeyInfoSha256 { get; }

        bool HasSignerSubjectPublicKeyInfoSha256 { get; }

        string TimestampUrl { get; }

        int SignToolTimeoutSeconds { get; }

        string AuthenticodeRevocationPolicy { get; }
    }

    private sealed class WorkerSigningDto : IWorkerLocalMachineSigningDto
    {
        public required string SignerPolicyId { get; init; }

        public required string TimestampPolicyId { get; init; }

        private string? _provider;

        public string? Provider
        {
            get => _provider;
            init
            {
                _provider = value;
                HasProvider = true;
            }
        }

        [JsonIgnore]
        public bool HasProvider { get; private set; }

        private WorkerLocalMachineSigningDto? _localMachineCertificate;

        public WorkerLocalMachineSigningDto? LocalMachineCertificate
        {
            get => _localMachineCertificate;
            init
            {
                _localMachineCertificate = value;
                HasLocalMachineCertificate = true;
            }
        }

        [JsonIgnore]
        public bool HasLocalMachineCertificate { get; private set; }

        private WorkerMicrosoftArtifactSigningDto? _microsoftArtifactSigning;

        public WorkerMicrosoftArtifactSigningDto? MicrosoftArtifactSigning
        {
            get => _microsoftArtifactSigning;
            init
            {
                _microsoftArtifactSigning = value;
                HasMicrosoftArtifactSigning = true;
            }
        }

        [JsonIgnore]
        public bool HasMicrosoftArtifactSigning { get; private set; }

        private string? _signToolPath;

        public string SignToolPath
        {
            get => _signToolPath ?? string.Empty;
            init
            {
                _signToolPath = value;
                HasSignToolPath = true;
            }
        }

        [JsonIgnore]
        public bool HasSignToolPath { get; private set; }

        private string? _signToolSha256;

        public string SignToolSha256
        {
            get => _signToolSha256 ?? string.Empty;
            init
            {
                _signToolSha256 = value;
                HasSignToolSha256 = true;
            }
        }

        [JsonIgnore]
        public bool HasSignToolSha256 { get; private set; }

        private string? _signToolFileVersion;

        public string SignToolFileVersion
        {
            get => _signToolFileVersion ?? string.Empty;
            init
            {
                _signToolFileVersion = value;
                HasSignToolFileVersion = true;
            }
        }

        [JsonIgnore]
        public bool HasSignToolFileVersion { get; private set; }

        private string? _signerCertificateThumbprint;

        public string SignerCertificateThumbprint
        {
            get => _signerCertificateThumbprint ?? string.Empty;
            init
            {
                _signerCertificateThumbprint = value;
                HasSignerCertificateThumbprint = true;
            }
        }

        [JsonIgnore]
        public bool HasSignerCertificateThumbprint { get; private set; }

        private string? _signerCertificateSha256;

        public string? SignerCertificateSha256
        {
            get => _signerCertificateSha256;
            init
            {
                _signerCertificateSha256 = value;
                HasSignerCertificateSha256 = true;
            }
        }

        [JsonIgnore]
        public bool HasSignerCertificateSha256 { get; private set; }

        private string? _signerSubjectPublicKeyInfoSha256;

        public string? SignerSubjectPublicKeyInfoSha256
        {
            get => _signerSubjectPublicKeyInfoSha256;
            init
            {
                _signerSubjectPublicKeyInfoSha256 = value;
                HasSignerSubjectPublicKeyInfoSha256 = true;
            }
        }

        [JsonIgnore]
        public bool HasSignerSubjectPublicKeyInfoSha256 { get; private set; }

        private string? _timestampUrl;

        public string TimestampUrl
        {
            get => _timestampUrl ?? string.Empty;
            init
            {
                _timestampUrl = value;
                HasTimestampUrl = true;
            }
        }

        [JsonIgnore]
        public bool HasTimestampUrl { get; private set; }

        private int _signToolTimeoutSeconds;

        public int SignToolTimeoutSeconds
        {
            get => _signToolTimeoutSeconds;
            init
            {
                _signToolTimeoutSeconds = value;
                HasSignToolTimeoutSeconds = true;
            }
        }

        [JsonIgnore]
        public bool HasSignToolTimeoutSeconds { get; private set; }

        private string? _authenticodeRevocationPolicy;

        public string AuthenticodeRevocationPolicy
        {
            get => _authenticodeRevocationPolicy ?? string.Empty;
            init
            {
                _authenticodeRevocationPolicy = value;
                HasAuthenticodeRevocationPolicy = true;
            }
        }

        [JsonIgnore]
        public bool HasAuthenticodeRevocationPolicy { get; private set; }
    }

    private sealed class WorkerLocalMachineSigningDto :
        IWorkerLocalMachineSigningDto
    {
        public required string SignToolPath { get; init; }

        public required string SignToolSha256 { get; init; }

        public required string SignToolFileVersion { get; init; }

        public required string SignerCertificateThumbprint { get; init; }

        private string? _signerCertificateSha256;

        public string? SignerCertificateSha256
        {
            get => _signerCertificateSha256;
            init
            {
                _signerCertificateSha256 = value;
                HasSignerCertificateSha256 = true;
            }
        }

        [JsonIgnore]
        public bool HasSignerCertificateSha256 { get; private set; }

        private string? _signerSubjectPublicKeyInfoSha256;

        public string? SignerSubjectPublicKeyInfoSha256
        {
            get => _signerSubjectPublicKeyInfoSha256;
            init
            {
                _signerSubjectPublicKeyInfoSha256 = value;
                HasSignerSubjectPublicKeyInfoSha256 = true;
            }
        }

        [JsonIgnore]
        public bool HasSignerSubjectPublicKeyInfoSha256 { get; private set; }

        public required string TimestampUrl { get; init; }

        public required int SignToolTimeoutSeconds { get; init; }

        public required string AuthenticodeRevocationPolicy { get; init; }
    }

    private sealed class WorkerMicrosoftArtifactSigningDto
    {
        public required string Region { get; init; }

        public required string CodeSigningAccountName { get; init; }

        public required string CertificateProfileName { get; init; }

        public required string SignToolPath { get; init; }

        public required string SignToolSha256 { get; init; }

        public required string SignToolFileVersion { get; init; }

        public required string DlibPath { get; init; }

        public required string DlibSha256 { get; init; }

        public required string DlibFileVersion { get; init; }

        public required string ClientToolsInventorySha256 { get; init; }

        public required string ExpectedPublisherSubjectNameSha256 { get; init; }

        public required string RequiredPublisherEnhancedKeyUsageOid { get; init; }

        public required List<string> TrustedPublisherRootThumbprints { get; init; }

        public required int SignToolTimeoutSeconds { get; init; }

        public required string AuthenticodeRevocationPolicy { get; init; }
    }

    private sealed class WorkerReceiptDto
    {
        public required string CertificateThumbprint { get; init; }

        public required WorkerTrustDto Trust { get; init; }
    }

    private sealed class WorkerTrustDto
    {
        public required string ExpectedSignerSpkiSha256 { get; init; }

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

        public required string RequiredEnhancedKeyUsageOid { get; init; }

        public required List<string> TrustedRootThumbprints { get; init; }

        public required List<string> ExtraCertificateThumbprints
        {
            get;
            init;
        }

        public required string RevocationPolicy { get; init; }

        public required int UrlRetrievalTimeoutSeconds { get; init; }
    }
}
