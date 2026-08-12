using ArtifactSigning.Profiles;
using ArtifactSigning.Protocol;

namespace ArtifactSigning.Gateway;

public sealed record GatewayClientIdentity
{
    public GatewayClientIdentity(
        string certificateSha256,
        string subjectPublicKeyInfoSha256)
    {
        GatewayContractRules.ValidateDigest(
            certificateSha256,
            nameof(certificateSha256));
        GatewayContractRules.ValidateSpki(
            subjectPublicKeyInfoSha256,
            nameof(subjectPublicKeyInfoSha256));
        CertificateSha256 = certificateSha256;
        SubjectPublicKeyInfoSha256 =
            subjectPublicKeyInfoSha256;
    }

    public string CertificateSha256 { get; }

    public string SubjectPublicKeyInfoSha256 { get; }
}

public sealed record GatewayVisibleProfile(
    string ProjectId,
    string ProfileId,
    int ProfileVersion,
    string RequestFormat,
    long MaximumRequestBytes,
    string ProfileSetSha256,
    string PackageId,
    string PackageVersion,
    string PackageSha256,
    string AssemblySha256,
    string DescriptorSha256);

public sealed class GatewayInstalledAuthorizationPolicy
{
    public GatewayInstalledAuthorizationPolicy(
        string projectId,
        string profileId,
        int profileVersion,
        GatewayClientIdentityConfiguration submitterClient,
        CmsTrustPolicy submitterTrust,
        GatewayClientIdentityConfiguration approverClient,
        CmsTrustPolicy approverTrust,
        bool requireDistinctSubmitterAndApprover)
    {
        ArgumentNullException.ThrowIfNull(submitterClient);
        ArgumentNullException.ThrowIfNull(submitterTrust);
        ArgumentNullException.ThrowIfNull(approverClient);
        ArgumentNullException.ThrowIfNull(approverTrust);
        SubmitterPolicy = new GatewaySubmitterPolicy(
            projectId,
            profileId,
            profileVersion,
            submitterTrust);
        ApproverPolicy = new GatewayApproverPolicy(
            projectId,
            profileId,
            profileVersion,
            approverTrust,
            requireDistinctSubmitterAndApprover);
        SubmitterClient = new GatewayClientIdentity(
            submitterClient.CertificateSha256,
            submitterClient.SubjectPublicKeyInfoSha256);
        ApproverClient = new GatewayClientIdentity(
            approverClient.CertificateSha256,
            approverClient.SubjectPublicKeyInfoSha256);
        if (!string.Equals(
                SubmitterClient.SubjectPublicKeyInfoSha256,
                submitterTrust.ExpectedSignerSpkiSha256,
                StringComparison.Ordinal)
            || !string.Equals(
                ApproverClient.SubjectPublicKeyInfoSha256,
                approverTrust.ExpectedSignerSpkiSha256,
                StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Gateway client and CMS policy identities differ.");
        }
    }

    public GatewaySubmitterPolicy SubmitterPolicy { get; }

    public GatewayApproverPolicy ApproverPolicy { get; }

    public GatewayClientIdentity SubmitterClient { get; }

    public GatewayClientIdentity ApproverClient { get; }

    internal bool MatchesRequest(GatewayRequestRecord request)
    {
        return string.Equals(
                SubmitterPolicy.ProjectId,
                request.ProjectId,
                StringComparison.Ordinal)
            && string.Equals(
                SubmitterPolicy.ProfileId,
                request.ProfileId,
                StringComparison.Ordinal)
            && SubmitterPolicy.ProfileVersion
                == request.ProfileVersion;
    }
}

public sealed class GatewayAuthorizationRegistry
{
    private readonly IReadOnlyList<
        GatewayInstalledAuthorizationPolicy> _policies;
    private readonly IReadOnlyList<
        GatewayAuditorConfiguration> _auditors;
    private readonly SigningProfileRegistry _profiles;
    private readonly HashSet<GatewayClientIdentity> _allowedClients;

    public GatewayAuthorizationRegistry(
        IEnumerable<GatewayInstalledAuthorizationPolicy> policies,
        IEnumerable<GatewayAuditorConfiguration> auditors,
        SigningProfileRegistry profiles)
    {
        ArgumentNullException.ThrowIfNull(policies);
        ArgumentNullException.ThrowIfNull(auditors);
        ArgumentNullException.ThrowIfNull(profiles);
        GatewayInstalledAuthorizationPolicy[] policyArray =
            policies.ToArray();
        GatewayAuditorConfiguration[] auditorArray =
            auditors.ToArray();
        if (policyArray.Length is 0 or > 32
            || policyArray.Any(item => item is null)
            || auditorArray.Length > 32
            || auditorArray.Any(item => item is null)
            || policyArray
                    .Select(item => (
                        item.SubmitterPolicy.ProjectId,
                        item.SubmitterPolicy.ProfileId,
                        item.SubmitterPolicy.ProfileVersion))
                    .Distinct()
                    .Count()
                != policyArray.Length
            || policyArray
                    .Select(item =>
                        item.SubmitterClient.CertificateSha256)
                    .Distinct(StringComparer.Ordinal)
                    .Count()
                != policyArray.Length)
        {
            throw new ArgumentException(
                "Gateway authorization registrations are invalid.");
        }

        foreach (GatewayInstalledAuthorizationPolicy policy
                 in policyArray)
        {
            ISigningProfile? profile = profiles.Resolve(
                policy.SubmitterPolicy.ProfileId,
                policy.SubmitterPolicy.ProfileVersion);
            if (profile is null
                || !profile.Descriptor.AllowedProjectIds.Contains(
                    policy.SubmitterPolicy.ProjectId,
                    StringComparer.Ordinal))
            {
                throw new ArgumentException(
                    "Gateway authorization references an uninstalled profile.");
            }
        }

        _policies = Array.AsReadOnly(policyArray);
        _auditors = Array.AsReadOnly(auditorArray);
        _profiles = profiles;
        _allowedClients = policyArray
            .SelectMany(item => new[]
            {
                item.SubmitterClient,
                item.ApproverClient,
            })
            .Concat(auditorArray.Select(item =>
                new GatewayClientIdentity(
                    item.Client.CertificateSha256,
                    item.Client.SubjectPublicKeyInfoSha256)))
            .ToHashSet();
    }

    public bool IsAllowedClient(GatewayClientIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        return _allowedClients.Contains(identity);
    }

    public GatewayInstalledAuthorizationPolicy?
        ResolveSubmitter(GatewayClientIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        return _policies.SingleOrDefault(item =>
            item.SubmitterClient == identity);
    }

    public GatewayInstalledAuthorizationPolicy?
        ResolveApprover(
            GatewayClientIdentity identity,
            GatewayRequestRecord request)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(request);
        return _policies.SingleOrDefault(item =>
            item.ApproverClient == identity
            && item.MatchesRequest(request));
    }

    public bool CanReadReview(
        GatewayClientIdentity identity,
        GatewayRequestRecord request)
    {
        return IsOriginalSubmitter(identity, request)
            || ResolveApprover(identity, request) is not null;
    }

    public bool CanReadStatus(
        GatewayClientIdentity identity,
        GatewayRequestRecord request)
    {
        return CanReadReview(identity, request)
            || IsAuditor(identity, request);
    }

    public bool CanDownload(
        GatewayClientIdentity identity,
        GatewayRequestRecord request)
    {
        return IsOriginalSubmitter(identity, request)
            || IsAuditor(identity, request);
    }

    public bool IsOriginalSubmitter(
        GatewayClientIdentity identity,
        GatewayRequestRecord request)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(request);
        return string.Equals(
            identity.SubjectPublicKeyInfoSha256,
            request.SubmitterSpkiSha256,
            StringComparison.Ordinal)
            && _policies.Any(item =>
                item.SubmitterClient == identity
                && item.MatchesRequest(request));
    }

    public IReadOnlyList<GatewayVisibleProfile>
        GetVisibleProfiles(GatewayClientIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        IEnumerable<(string ProjectId, string ProfileId, int Version)>
            visible = _policies
                .Where(item =>
                    item.SubmitterClient == identity
                    || item.ApproverClient == identity)
                .Select(item => (
                    item.SubmitterPolicy.ProjectId,
                    item.SubmitterPolicy.ProfileId,
                    item.SubmitterPolicy.ProfileVersion))
                .Concat(_auditors
                    .Where(item => ClientMatches(
                        identity,
                        item.Client))
                    .Select(item => (
                        item.ProjectId,
                        item.ProfileId,
                        item.ProfileVersion)))
                .Distinct();
        return visible
            .Select(item =>
            {
                ISigningProfile profile = _profiles.Resolve(
                        item.ProfileId,
                        item.Version)
                    ?? throw new InvalidOperationException(
                        "Visible Gateway profile is not installed.");
                SigningProfilePackageDescriptor package =
                    _profiles.ResolvePackage(
                        item.ProfileId,
                        item.Version)
                    ?? throw new InvalidOperationException(
                        "Visible Gateway profile package is not installed.");
                return new GatewayVisibleProfile(
                    item.ProjectId,
                    item.ProfileId,
                    item.Version,
                    ArtifactSigningRequestV1.FormatIdentifier,
                    profile.Descriptor.MaximumRequestBytes,
                    _profiles.PackageSetSha256
                        ?? throw new InvalidOperationException(
                            "Visible Gateway profiles require package-set registration."),
                    package.PackageId,
                    package.PackageVersion,
                    package.PackageSha256,
                    package.AssemblySha256,
                    package.DescriptorSha256);
            })
            .OrderBy(item => item.ProjectId, StringComparer.Ordinal)
            .ThenBy(item => item.ProfileId, StringComparer.Ordinal)
            .ThenBy(item => item.ProfileVersion)
            .ToArray();
    }

    public bool CanReadAuditHead(
        GatewayClientIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        return _auditors.Any(item =>
            ClientMatches(identity, item.Client));
    }

    private bool IsAuditor(
        GatewayClientIdentity identity,
        GatewayRequestRecord request)
    {
        return _auditors.Any(item =>
            ClientMatches(identity, item.Client)
            && string.Equals(
                item.ProjectId,
                request.ProjectId,
                StringComparison.Ordinal)
            && string.Equals(
                item.ProfileId,
                request.ProfileId,
                StringComparison.Ordinal)
            && item.ProfileVersion == request.ProfileVersion);
    }

    private static bool ClientMatches(
        GatewayClientIdentity identity,
        GatewayClientIdentityConfiguration configured)
    {
        return string.Equals(
                identity.CertificateSha256,
                configured.CertificateSha256,
                StringComparison.Ordinal)
            && string.Equals(
                identity.SubjectPublicKeyInfoSha256,
                configured.SubjectPublicKeyInfoSha256,
                StringComparison.Ordinal);
    }
}
