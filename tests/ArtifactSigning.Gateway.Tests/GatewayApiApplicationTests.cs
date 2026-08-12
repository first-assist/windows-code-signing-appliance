using System.Formats.Tar;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ArtifactSigning.Profiles;
using ArtifactSigning.Protocol;
using ArtifactSigning.TestProfile;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Xunit;

namespace ArtifactSigning.Gateway.Tests;

public sealed class GatewayApiApplicationTests
{
    private const string RequiredEkuOid =
        "1.3.6.1.5.5.7.3.2";

    private static readonly DateTimeOffset Now =
        new(2026, 7, 29, 17, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task EnforcesIdentityAndReturnsPascalCaseBoundedViews()
    {
        using GatewayStateTestEnvironment stateEnvironment = new();
        GatewayStateStore store =
            stateEnvironment.CreateStore();
        using GatewayCmsTestCertificateAuthority authority =
            GatewayCmsTestCertificateAuthority.Create(
                Now.AddDays(-1),
                Now.AddDays(1));
        using GatewayCmsTestIdentity submitter =
            CreateIdentity(authority);
        using GatewayCmsTestIdentity approver =
            CreateIdentity(authority);
        using GatewayCmsTestIdentity unauthorized =
            CreateIdentity(authority);
        using GatewayCmsTestIdentity auditor =
            CreateIdentity(authority);
        using GatewayCmsTestIdentity receipt =
            CreateIdentity(authority);
        using X509Certificate2 publicRoot =
            authority.ExportPublicCertificate();
        CmsTrustPolicy submitterTrust = CreateTrust(
            submitter,
            publicRoot);
        CmsTrustPolicy approverTrust = CreateTrust(
            approver,
            publicRoot);
        CmsTrustPolicy receiptTrust = CreateTrust(
            receipt,
            publicRoot);
        GatewayClientIdentityConfiguration submitterClient =
            Client(submitter);
        GatewayClientIdentityConfiguration approverClient =
            Client(approver);
        GatewayInstalledAuthorizationPolicy installed = new(
            ExampleEndpointBundleV1.ProjectId,
            ExampleEndpointBundleV1.ProfileId,
            ExampleEndpointBundleV1.ProfileVersion,
            submitterClient,
            submitterTrust,
            approverClient,
            approverTrust,
            requireDistinctSubmitterAndApprover: true);
        SigningProfilePackageSet profilePackages =
            ExampleProfilePackage.CreatePackageSet();
        SigningProfileRegistry profiles =
            SigningProfileRegistry.FromPackageSet(profilePackages);
        GatewayAuthorizationRegistry authorization = new(
            [installed],
            [
                new GatewayAuditorConfiguration(
                    ExampleEndpointBundleV1.ProjectId,
                    ExampleEndpointBundleV1.ProfileId,
                    ExampleEndpointBundleV1.ProfileVersion,
                    Client(auditor)),
            ],
            profiles);
        ArtifactSigningRequestV1 request = CreateRequest();
        string digest = new('d', 64);
        _ = store.AdmitPending(
            request,
            digest,
            submitter.SubjectPublicKeyInfoSha256,
            Now);
        WriteReviewRecord(
            store.Layout,
            request.RequestId);
        WriteAuditAnchor(
            store.Layout,
            receipt);
        GatewayAuditAnchorReader auditReader = new(
            store.Layout,
            receiptTrust);
        GatewayReadinessProbe readinessProbe = new(
            store,
            auditReader,
            timeProvider: new FixedTimeProvider(Now));

        X509Certificate2? currentCertificate =
            submitter.Certificate;
        WebApplicationBuilder builder =
            WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        GatewayApiApplication.AddGatewayApiServices(
            builder.Services);
        await using WebApplication application =
            builder.Build();
        application.Use(async (context, next) =>
        {
            context.Connection.ClientCertificate =
                currentCertificate;
            await next(context).ConfigureAwait(false);
        });
        GatewayApiRuntime runtime = new(
            store,
            authorization,
            profiles,
            new GatewaySubmissionProcessor(
                store,
                profiles,
                new FixedTimeProvider(Now)),
            new GatewayApprovalProcessor(
                store,
                new TestReadyRecordAccessController(),
                new FixedTimeProvider(Now)),
            new SuccessfulNotifier(),
            new GatewayResultProcessor(
                store,
                profiles,
                receiptTrust,
                new FixedTimeProvider(Now)),
            new FixedTimeProvider(Now),
            auditReader,
            readinessProbe);
        GatewayApiApplication.Configure(
            application,
            runtime);
        await application.StartAsync(
            TestContext.Current.CancellationToken);
        using HttpClient client =
            application.GetTestClient();

        using HttpResponseMessage profilesResponse =
            await client.GetAsync(
                new Uri("/v1/profiles", UriKind.Relative),
                TestContext.Current.CancellationToken);
        string profilesJson =
            await profilesResponse.Content.ReadAsStringAsync(
                TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, profilesResponse.StatusCode);
        Assert.Contains(
            "\"Profiles\"",
            profilesJson,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "\"profiles\"",
            profilesJson,
            StringComparison.Ordinal);
        Assert.Contains(
            "\"Format\":\"ArtifactSigningProfilesResponseV2\"",
            profilesJson,
            StringComparison.Ordinal);
        Assert.Contains(
            string.Concat(
                "\"ProfileSetSha256\":\"",
                profilePackages.PackageSetSha256,
                "\""),
            profilesJson,
            StringComparison.Ordinal);
        SigningProfilePackageDescriptor package =
            profilePackages.ResolvePackage(
                ExampleEndpointBundleV1.ProfileId,
                ExampleEndpointBundleV1.ProfileVersion)
            ?? throw new InvalidOperationException("Example package is absent.");
        Assert.Contains(
            string.Concat("\"PackageId\":\"", package.PackageId, "\""),
            profilesJson,
            StringComparison.Ordinal);
        Assert.Contains(
            string.Concat(
                "\"PackageVersion\":\"",
                package.PackageVersion,
                "\""),
            profilesJson,
            StringComparison.Ordinal);
        Assert.Contains(
            string.Concat(
                "\"PackageSha256\":\"",
                package.PackageSha256,
                "\""),
            profilesJson,
            StringComparison.Ordinal);
        Assert.Contains(
            string.Concat(
                "\"AssemblySha256\":\"",
                package.AssemblySha256,
                "\""),
            profilesJson,
            StringComparison.Ordinal);
        Assert.Contains(
            string.Concat(
                "\"DescriptorSha256\":\"",
                package.DescriptorSha256,
                "\""),
            profilesJson,
            StringComparison.Ordinal);
        Assert.Equal(
            "no-store",
            profilesResponse.Headers.CacheControl?.ToString());

        using HttpResponseMessage status =
            await client.GetAsync(
                new Uri(
                    $"/v1/requests/{request.RequestId:D}",
                    UriKind.Relative),
                TestContext.Current.CancellationToken);
        string statusJson =
            await status.Content.ReadAsStringAsync(
                TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, status.StatusCode);
        Assert.Contains(
            "\"CanApprove\":false",
            statusJson,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "Reason",
            statusJson,
            StringComparison.Ordinal);

        using HttpResponseMessage review =
            await client.GetAsync(
                new Uri(
                    $"/v1/requests/{request.RequestId:D}/review",
                    UriKind.Relative),
                TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, review.StatusCode);
        using Stream reviewBody =
            await review.Content.ReadAsStreamAsync(
                TestContext.Current.CancellationToken);
        using TarReader reader = new(reviewBody);
        List<string> names = [];
        TarEntry? entry;
        while ((entry = await reader.GetNextEntryAsync(
                       copyData: false,
                       TestContext.Current.CancellationToken))
                   is not null)
        {
            names.Add(entry.Name);
        }

        Assert.Equal(
            new[]
            {
                GatewaySubmissionProcessor.RequestJsonFileName,
                GatewaySubmissionProcessor
                    .RequestSignatureFileName,
            },
            names);

        currentCertificate = approver.Certificate;
        using HttpResponseMessage approverStatus =
            await client.GetAsync(
                new Uri(
                    $"/v1/requests/{request.RequestId:D}",
                    UriKind.Relative),
                TestContext.Current.CancellationToken);
        Assert.Contains(
            "\"CanApprove\":true",
            await approverStatus.Content.ReadAsStringAsync(
                TestContext.Current.CancellationToken),
            StringComparison.Ordinal);

        currentCertificate = auditor.Certificate;
        using HttpResponseMessage audit =
            await client.GetAsync(
                new Uri(
                    "/v1/audit/head",
                    UriKind.Relative),
                TestContext.Current.CancellationToken);
        string auditJson =
            await audit.Content.ReadAsStringAsync(
                TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, audit.StatusCode);
        Assert.Contains(
            "\"Format\":\"ArtifactSigningAuditHeadV1\"",
            auditJson,
            StringComparison.Ordinal);
        Assert.Contains(
            "\"WorkerAnchorSignature\"",
            auditJson,
            StringComparison.Ordinal);
        using HttpResponseMessage ready =
            await client.GetAsync(
                new Uri(
                    "/v1/health/ready",
                    UriKind.Relative),
                TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, ready.StatusCode);
        Assert.Equal(
            "{\"Status\":\"Ready\"}",
            await ready.Content.ReadAsStringAsync(
                TestContext.Current.CancellationToken));

        currentCertificate = submitter.Certificate;
        using HttpResponseMessage auditDenied =
            await client.GetAsync(
                new Uri(
                    "/v1/audit/head",
                    UriKind.Relative),
                TestContext.Current.CancellationToken);
        Assert.Equal(
            HttpStatusCode.Forbidden,
            auditDenied.StatusCode);

        currentCertificate = unauthorized.Certificate;
        using HttpResponseMessage denied =
            await client.GetAsync(
                new Uri("/v1/profiles", UriKind.Relative),
                TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        Assert.Contains(
            "\"Code\":\"ClientNotAuthorized\"",
            await denied.Content.ReadAsStringAsync(
                TestContext.Current.CancellationToken),
            StringComparison.Ordinal);

        currentCertificate = null;
        using HttpResponseMessage missing =
            await client.GetAsync(
                new Uri(
                    "/v1/health/live",
                    UriKind.Relative),
                TestContext.Current.CancellationToken);
        Assert.Equal(
            HttpStatusCode.Unauthorized,
            missing.StatusCode);

        currentCertificate = submitter.Certificate;
        using ByteArrayContent cancelContent = new([]);
        using HttpResponseMessage cancelled =
            await client.PostAsync(
                new Uri(
                    $"/v1/requests/{request.RequestId:D}/cancel",
                    UriKind.Relative),
                cancelContent,
                TestContext.Current.CancellationToken);
        Assert.Equal(
            HttpStatusCode.Accepted,
            cancelled.StatusCode);
        Assert.Equal(
            RequestState.Cancelled,
            store.GetRequest(request.RequestId)?.State);
    }

    [Fact]
    public void WorkerDispatchTransitionIsIdempotentAndDisablesCancellation()
    {
        using GatewayStateTestEnvironment environment = new();
        GatewayStateStore store = environment.CreateStore();
        ArtifactSigningRequestV1 request = CreateRequest();
        string requestDigest = new('e', 64);
        GatewayRequestRecord pending = store.AdmitPending(
                request,
                requestDigest,
                new string('a', 64),
                Now)
            .Request!;
        ArtifactSigningApprovalV1 approval = new(
            request.RequestId,
            requestDigest,
            ApprovalDecision.Approve,
            "Approved for dispatch",
            Now,
            Now.AddMinutes(1),
            CanonicalNonce(0x02));
        GatewayRequestRecord approved = store.TryRecordApproval(
                request.RequestId,
                requestDigest,
                pending.RowVersion,
                approval,
                new string('b', 64),
                new string('f', 64),
                requireDistinctSubmitterAndApprover: true,
                Now)
            .Request!;

        GatewayMutationResult first =
            store.TryMarkWorkerDispatched(
                request.RequestId,
                requestDigest,
                approved.RowVersion,
                Now.AddSeconds(1));
        GatewayMutationResult retry =
            store.TryMarkWorkerDispatched(
                request.RequestId,
                requestDigest,
                approved.RowVersion,
                Now.AddSeconds(2));
        GatewayMutationResult cancel = store.TryCancel(
            request.RequestId,
            requestDigest,
            first.Request!.RowVersion,
            Now.AddSeconds(2));

        Assert.Equal(
            GatewayMutationOutcome.Applied,
            first.Outcome);
        Assert.Equal(RequestState.Signing, first.Request?.State);
        Assert.Equal(
            GatewayMutationOutcome.AlreadyApplied,
            retry.Outcome);
        Assert.Equal(
            GatewayMutationOutcome.StateMismatch,
            cancel.Outcome);
        store.VerifyIntegrity();
    }

    private static GatewayCmsTestIdentity CreateIdentity(
        GatewayCmsTestCertificateAuthority authority)
    {
        return GatewayCmsTestIdentity.CreateIssued(
            authority,
            Now.AddHours(-1),
            Now.AddHours(1),
            RequiredEkuOid);
    }

    private static CmsTrustPolicy CreateTrust(
        GatewayCmsTestIdentity identity,
        X509Certificate2 root)
    {
        return new CmsTrustPolicy(
            identity.SubjectPublicKeyInfoSha256,
            RequiredEkuOid,
            [root],
            CmsRevocationPolicy.DisposableTestNoCheck,
            TimeSpan.FromSeconds(1));
    }

    private static GatewayClientIdentityConfiguration Client(
        GatewayCmsTestIdentity identity)
    {
        return new GatewayClientIdentityConfiguration(
            CertificateIdentity.ComputeCertificateSha256(
                identity.Certificate),
            identity.SubjectPublicKeyInfoSha256);
    }

    private static ArtifactSigningRequestV1 CreateRequest()
    {
        return new ArtifactSigningRequestV1(
            Guid.NewGuid(),
            ExampleEndpointBundleV1.ProjectId,
            ExampleEndpointBundleV1.ProfileId,
            ExampleEndpointBundleV1.ProfileVersion,
            ExampleEndpointBundleV1.SourceRepository,
            "0123456789abcdef0123456789abcdef01234567",
            "1.2.3",
            Now.AddMinutes(-1),
            Now.AddMinutes(5),
            CanonicalNonce(0x01),
            ExampleEndpointBundleV1.SignerPolicyId,
            ExampleEndpointBundleV1.TimestampPolicyId,
            [
                new RequestArtifactV1(
                    "Manifest",
                    "release-manifest.json",
                    1,
                    new string('1', 64)),
            ]);
    }

    private static void WriteReviewRecord(
        GatewayDirectoryLayout layout,
        Guid requestId)
    {
        string pending =
            layout.GetPendingRequestDirectory(requestId);
        Directory.CreateDirectory(pending);
        Directory.CreateDirectory(Path.Combine(
            pending,
            GatewaySubmissionProcessor.BundleDirectoryName));
        File.WriteAllBytes(
            Path.Combine(
                pending,
                GatewaySubmissionProcessor.RequestJsonFileName),
            Encoding.UTF8.GetBytes("{}"));
        File.WriteAllBytes(
            Path.Combine(
                pending,
                GatewaySubmissionProcessor
                    .RequestSignatureFileName),
            [0x01]);
    }

    private static void WriteAuditAnchor(
        GatewayDirectoryLayout layout,
        GatewayCmsTestIdentity receipt)
    {
        WorkerAuditAnchorV1 anchor = new(
            1,
            new string('a', 64),
            GatewayReadinessProbe.RequiredWorkerVersion,
            workerReady: true,
            timestampDependencyReady: true,
            Now,
            Now.AddMinutes(2),
            receipt.SubjectPublicKeyInfoSha256);
        byte[] json =
            WorkerAuditAnchorJson.Serialize(anchor);
        string digest = Convert.ToHexStringLower(
            SHA256.HashData(json));
        File.WriteAllBytes(
            Path.Combine(
                layout.WorkerStatusRoot,
                WorkerAuditAnchorFiles
                    .GetJsonFileName(digest)),
            json);
        File.WriteAllBytes(
            Path.Combine(
                layout.WorkerStatusRoot,
                WorkerAuditAnchorFiles
                    .GetSignatureFileName(digest)),
            receipt.Sign(json, detached: true));
    }

    private static string CanonicalNonce(byte value)
    {
        return Convert.ToBase64String(
                Enumerable.Repeat(value, 32).ToArray())
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private sealed class SuccessfulNotifier :
        IGatewayWorkerNotifier
    {
        public ValueTask<GatewayWorkerNotificationResult>
            NotifyAsync(
                Guid requestId,
                CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(
                new GatewayWorkerNotificationResult(
                    GatewayWorkerNotificationError.None));
        }
    }

    private sealed class FixedTimeProvider(
        DateTimeOffset value) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow()
        {
            return value;
        }
    }
}
