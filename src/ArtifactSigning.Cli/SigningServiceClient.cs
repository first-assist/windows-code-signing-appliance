using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using ArtifactSigning.Profiles;
using ArtifactSigning.Protocol;

namespace ArtifactSigning.Cli;

internal sealed class CliServiceException : Exception
{
    internal CliServiceException(
        HttpStatusCode statusCode,
        string code)
        : base("The signing service rejected the operation.")
    {
        StatusCode = statusCode;
        Code = code;
    }

    internal HttpStatusCode StatusCode { get; }

    internal string Code { get; }
}

internal sealed record CliVisibleProfile(
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

internal sealed record CliRequestAccepted(
    Guid RequestId,
    string RequestDigest,
    RequestState State,
    string ProjectId,
    string ProfileId,
    int ProfileVersion,
    DateTimeOffset ExpiresAt);

internal sealed record CliDecisionAccepted(
    Guid RequestId,
    string RequestDigest,
    RequestState State);

internal sealed record CliRequestStatus(
    Guid RequestId,
    string RequestDigest,
    RequestState State,
    string ResultCode,
    string ProjectId,
    string ProfileId,
    int ProfileVersion,
    string SourceRepository,
    string SourceCommit,
    string ReleaseVersion,
    DateTimeOffset RequestedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    bool CanApprove,
    bool CanDownload);

internal sealed class SigningServiceClient : IDisposable
{
    internal const string RequestContentType =
        "application/vnd.artifact-signing.request.v1+tar";
    internal const string ApprovalContentType =
        "application/vnd.artifact-signing.approval.v1+pkcs7";
    internal const string ReviewContentType =
        "application/vnd.artifact-signing.review.v1+tar";
    internal const string ResultContentType =
        "application/vnd.artifact-signing.result.v1+tar";
    internal const long MaximumArchiveResponseBytes =
        101L * 1024 * 1024;

    private const int MaximumJsonBytes = 128 * 1024;

    private static readonly JsonSerializerOptions
        JsonOptions = new()
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

    private readonly HttpClient _client;

    internal SigningServiceClient(
        CliConfiguration configuration,
        X509Certificate2 clientCertificate,
        HttpMessageHandler? handler = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(clientCertificate);
        _client = handler is null
            ? CreateHttpClient(
                configuration,
                clientCertificate)
            : new HttpClient(
                handler,
                disposeHandler: true)
            {
                BaseAddress = configuration.ServiceUri,
                Timeout = TimeSpan.FromSeconds(125),
            };
    }

    internal async Task<IReadOnlyList<CliVisibleProfile>>
        GetProfilesAsync(
            CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(
            HttpMethod.Get,
            "v1/profiles");
        using HttpResponseMessage response =
            await SendAsync(request, cancellationToken)
                .ConfigureAwait(false);
        RequireStatus(response, HttpStatusCode.OK);
        CliProfilesResponse value =
            await ReadJsonAsync<CliProfilesResponse>(
                    response,
                    cancellationToken)
                .ConfigureAwait(false);
        if (!string.Equals(
                value.Format,
                CliProfilesResponse.FormatIdentifier,
                StringComparison.Ordinal)
            || value.Profiles is null
            || value.Profiles.Count is 0 or > 32
            || value.Profiles.Any(item =>
                item is null || !IsValidProfile(item))
            || value.Profiles
                .Select(item => (
                    item.ProjectId,
                    item.ProfileId,
                    item.ProfileVersion))
                .Distinct()
                .Count() != value.Profiles.Count)
        {
            throw new InvalidDataException(
                "Signing service response is invalid.");
        }

        return value.Profiles;
    }

    internal async Task<CliRequestAccepted> SubmitAsync(
        Stream archive,
        long archiveLength,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(archive);
        using HttpRequestMessage request = new(
            HttpMethod.Post,
            "v1/requests");
        request.Content = new StreamContent(archive);
        request.Content.Headers.ContentType =
            MediaTypeHeaderValue.Parse(
                RequestContentType);
        request.Content.Headers.ContentLength =
            archiveLength;
        using HttpResponseMessage response =
            await SendAsync(request, cancellationToken)
                .ConfigureAwait(false);
        RequireStatus(
            response,
            HttpStatusCode.Accepted);
        CliRequestAccepted accepted =
            await ReadJsonAsync<CliRequestAccepted>(
                response,
                cancellationToken)
            .ConfigureAwait(false);
        ValidateAccepted(accepted);
        return accepted;
    }

    internal async Task<CliRequestStatus> GetStatusAsync(
        Guid requestId,
        CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(
            HttpMethod.Get,
            RequestPath(requestId));
        using HttpResponseMessage response =
            await SendAsync(request, cancellationToken)
                .ConfigureAwait(false);
        RequireStatus(response, HttpStatusCode.OK);
        CliRequestStatus status =
            await ReadJsonAsync<CliRequestStatus>(
                response,
                cancellationToken)
            .ConfigureAwait(false);
        ValidateStatus(status);
        return status;
    }

    internal async Task<byte[]> GetReviewAsync(
        Guid requestId,
        CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(
            HttpMethod.Get,
            string.Concat(
                RequestPath(requestId),
                "/review"));
        using HttpResponseMessage response =
            await SendAsync(request, cancellationToken)
                .ConfigureAwait(false);
        RequireStatus(response, HttpStatusCode.OK);
        RequireContentType(response, ReviewContentType);
        return await ReadBoundedBytesAsync(
                response,
                DetachedCmsSignatureVerifier
                    .MaximumSignatureBytes
                    + ArtifactSigningRequestJsonParser
                        .MaximumRequestJsonBytes
                    + 4096,
                cancellationToken)
            .ConfigureAwait(false);
    }

    internal async Task<CliDecisionAccepted> DecideAsync(
        Guid requestId,
        byte[] approvalCms,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(approvalCms);
        using HttpRequestMessage request = new(
            HttpMethod.Post,
            string.Concat(
                RequestPath(requestId),
                "/approvals"));
        request.Content = new ByteArrayContent(approvalCms);
        request.Content.Headers.ContentType =
            MediaTypeHeaderValue.Parse(
                ApprovalContentType);
        using HttpResponseMessage response =
            await SendAsync(request, cancellationToken)
                .ConfigureAwait(false);
        RequireStatus(
            response,
            HttpStatusCode.Accepted);
        CliDecisionAccepted accepted =
            await ReadJsonAsync<CliDecisionAccepted>(
                response,
                cancellationToken)
            .ConfigureAwait(false);
        ValidateDecision(accepted);
        return accepted;
    }

    internal async Task<CliDecisionAccepted> CancelAsync(
        Guid requestId,
        CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(
            HttpMethod.Post,
            string.Concat(
                RequestPath(requestId),
                "/cancel"))
        {
            Content = new ByteArrayContent([]),
        };
        using HttpResponseMessage response =
            await SendAsync(request, cancellationToken)
                .ConfigureAwait(false);
        RequireStatus(
            response,
            HttpStatusCode.Accepted);
        CliDecisionAccepted accepted =
            await ReadJsonAsync<CliDecisionAccepted>(
                response,
                cancellationToken)
            .ConfigureAwait(false);
        ValidateDecision(accepted);
        return accepted;
    }

    internal async Task DownloadAsync(
        Guid requestId,
        Stream destination,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        using HttpRequestMessage request = new(
            HttpMethod.Get,
            string.Concat(
                RequestPath(requestId),
                "/bundle"));
        using HttpResponseMessage response =
            await SendAsync(request, cancellationToken)
                .ConfigureAwait(false);
        RequireStatus(response, HttpStatusCode.OK);
        RequireContentType(response, ResultContentType);
        long? declaredLength =
            response.Content.Headers.ContentLength;
        if (declaredLength is <= 0
            || declaredLength
                > MaximumArchiveResponseBytes)
        {
            throw new InvalidDataException(
                "Signing service response is invalid.");
        }

        using Stream input =
            await response.Content.ReadAsStreamAsync(
                    cancellationToken)
                .ConfigureAwait(false);
        byte[] buffer = new byte[64 * 1024];
        long total = 0;
        while (true)
        {
            int read = await input.ReadAsync(
                    buffer,
                    cancellationToken)
                .ConfigureAwait(false);
            if (read is 0)
            {
                break;
            }

            total = checked(total + read);
            if (total > MaximumArchiveResponseBytes)
            {
                throw new InvalidDataException(
                    "Signing service response is oversized.");
            }

            await destination.WriteAsync(
                    buffer.AsMemory(0, read),
                    cancellationToken)
                .ConfigureAwait(false);
        }

        if (total != declaredLength)
        {
            throw new InvalidDataException(
                "Signing service response is incomplete.");
        }
    }

    public void Dispose()
    {
        _client.Dispose();
    }

    private async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        HttpResponseMessage response =
            await _client.SendAsync(
                    request,
                    HttpCompletionOption
                        .ResponseHeadersRead,
                    cancellationToken)
                .ConfigureAwait(false);
        if (response.IsSuccessStatusCode)
        {
            return response;
        }

        try
        {
            CliProblem problem =
                await ReadJsonAsync<CliProblem>(
                        response,
                        cancellationToken,
                        requireSuccess: false)
                    .ConfigureAwait(false);
            throw new CliServiceException(
                response.StatusCode,
                IsSafeCode(problem.Code)
                    ? problem.Code
                    : "SigningUnavailable");
        }
        finally
        {
            response.Dispose();
        }
    }

    private static async Task<T> ReadJsonAsync<T>(
        HttpResponseMessage response,
        CancellationToken cancellationToken,
        bool requireSuccess = true)
    {
        if (requireSuccess
            && !response.IsSuccessStatusCode)
        {
            throw new InvalidDataException(
                "Signing service response is invalid.");
        }

        RequireContentType(
            response,
            "application/json");
        byte[] content = await ReadBoundedBytesAsync(
                response,
                MaximumJsonBytes,
                cancellationToken)
            .ConfigureAwait(false);
        try
        {
            return JsonSerializer.Deserialize<T>(
                    content,
                    JsonOptions)
                ?? throw new InvalidDataException(
                    "Signing service response is invalid.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Signing service response is invalid.",
                exception);
        }
    }

    private static async Task<byte[]> ReadBoundedBytesAsync(
        HttpResponseMessage response,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        long? declaredLength =
            response.Content.Headers.ContentLength;
        if (declaredLength == 0
            || declaredLength > maximumBytes)
        {
            throw new InvalidDataException(
                "Signing service response is invalid.");
        }

        using Stream input =
            await response.Content.ReadAsStreamAsync(
                    cancellationToken)
                .ConfigureAwait(false);
        using MemoryStream output = new();
        byte[] buffer = new byte[16 * 1024];
        int total = 0;
        while (true)
        {
            int read = await input.ReadAsync(
                    buffer,
                    cancellationToken)
                .ConfigureAwait(false);
            if (read is 0)
            {
                if (total is 0
                    || declaredLength.HasValue
                    && total != declaredLength.Value)
                {
                    throw new InvalidDataException(
                        "Signing service response is incomplete.");
                }

                return output.ToArray();
            }

            if (read > maximumBytes - total)
            {
                throw new InvalidDataException(
                    "Signing service response is oversized.");
            }

            await output.WriteAsync(
                    buffer.AsMemory(0, read),
                    cancellationToken)
                .ConfigureAwait(false);
            total += read;
        }
    }

    private static void RequireContentType(
        HttpResponseMessage response,
        string expected)
    {
        MediaTypeHeaderValue? contentType =
            response.Content.Headers.ContentType;
        bool isJson = string.Equals(
            expected,
            "application/json",
            StringComparison.Ordinal);
        bool parametersValid = contentType is not null
            && (contentType.Parameters.Count is 0
                || isJson
                && contentType.Parameters.Count is 1
                && string.Equals(
                    contentType.CharSet,
                    "utf-8",
                    StringComparison.OrdinalIgnoreCase));
        if (contentType is null
            || !parametersValid
            || !string.Equals(
                contentType.MediaType,
                expected,
                StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                "Signing service response content type is invalid.");
        }
    }

    private static void RequireStatus(
        HttpResponseMessage response,
        HttpStatusCode expected)
    {
        if (response.StatusCode != expected)
        {
            throw new InvalidDataException(
                "Signing service response status is invalid.");
        }
    }

    private static bool IsValidProfile(
        CliVisibleProfile profile)
    {
        return IsSafeCode(profile.ProjectId)
            && IsSafeCode(profile.ProfileId)
            && profile.ProfileVersion > 0
            && string.Equals(
                profile.RequestFormat,
                ArtifactSigningRequestV1.FormatIdentifier,
                StringComparison.Ordinal)
            && profile.MaximumRequestBytes is > 0
                and <= ClosedTarArchivePolicy
                    .MaximumArchiveEntryBytes
            && IsLowerSha256(profile.ProfileSetSha256)
            && IsSafeCode(profile.PackageId)
            && SigningProfilePackageDescriptor.IsCanonicalPackageVersion(
                profile.PackageVersion)
            && IsLowerSha256(profile.PackageSha256)
            && IsLowerSha256(profile.AssemblySha256)
            && IsLowerSha256(profile.DescriptorSha256);
    }

    private static void ValidateAccepted(
        CliRequestAccepted accepted)
    {
        if (accepted.RequestId == Guid.Empty
            || !IsLowerSha256(
                accepted.RequestDigest)
            || !Enum.IsDefined(accepted.State)
            || !IsSafeCode(accepted.ProjectId)
            || !IsSafeCode(accepted.ProfileId)
            || accepted.ProfileVersion <= 0
            || !IsWholeSecondUtc(accepted.ExpiresAt))
        {
            throw new InvalidDataException(
                "Signing service response is invalid.");
        }
    }

    private static void ValidateDecision(
        CliDecisionAccepted accepted)
    {
        if (accepted.RequestId == Guid.Empty
            || !IsLowerSha256(
                accepted.RequestDigest)
            || !Enum.IsDefined(accepted.State))
        {
            throw new InvalidDataException(
                "Signing service response is invalid.");
        }
    }

    private static void ValidateStatus(
        CliRequestStatus status)
    {
        if (status.RequestId == Guid.Empty
            || !IsLowerSha256(status.RequestDigest)
            || !Enum.IsDefined(status.State)
            || !IsSafeCode(status.ResultCode)
            || !IsSafeCode(status.ProjectId)
            || !IsSafeCode(status.ProfileId)
            || status.ProfileVersion <= 0
            || !IsPrintableAscii(
                status.SourceRepository,
                128)
            || !IsLowerHex(
                status.SourceCommit,
                status.SourceCommit.Length)
            || status.SourceCommit.Length is not
                (40 or 64)
            || !IsPrintableAscii(
                status.ReleaseVersion,
                64)
            || !IsWholeSecondUtc(status.RequestedAt)
            || !IsWholeSecondUtc(status.ExpiresAt)
            || !IsWholeSecondUtc(status.CreatedAt)
            || !IsWholeSecondUtc(status.UpdatedAt))
        {
            throw new InvalidDataException(
                "Signing service response is invalid.");
        }
    }

    private static bool IsWholeSecondUtc(
        DateTimeOffset value)
    {
        return value.Offset == TimeSpan.Zero
            && value.Ticks
                % TimeSpan.TicksPerSecond is 0;
    }

    private static bool IsPrintableAscii(
        string value,
        int maximumCharacters)
    {
        return value.Length is > 0
            && value.Length <= maximumCharacters
            && value[0] is not ' '
            && value[^1] is not ' '
            && value.All(character =>
                character is >= '!' and <= '~');
    }

    private static bool IsLowerSha256(string value)
    {
        return IsLowerHex(value, 64);
    }

    private static bool IsLowerHex(
        string value,
        int length)
    {
        return value.Length == length
            && value.All(character =>
                character is >= '0' and <= '9'
                    or >= 'a' and <= 'f');
    }

    private static HttpClient CreateHttpClient(
        CliConfiguration configuration,
        X509Certificate2 clientCertificate)
    {
        HttpClientHandler handler = new()
        {
            AllowAutoRedirect = false,
            AutomaticDecompression =
                DecompressionMethods.None,
            CheckCertificateRevocationList =
                RequiresTlsCertificateRevocationCheck(
                    configuration.Mode),
            MaxConnectionsPerServer = 4,
            MaxResponseHeadersLength = 16,
            UseCookies = false,
            UseProxy = false,
        };
        handler.ClientCertificates.Add(
            clientCertificate);
        handler.ServerCertificateCustomValidationCallback =
            (_, certificate, _, errors) =>
                ValidateServerCertificate(
                    certificate,
                    errors,
                    configuration);
        HttpClient client = new(
            handler,
            disposeHandler: true);
        client.BaseAddress = configuration.ServiceUri;
        client.Timeout = TimeSpan.FromSeconds(125);
        return client;
    }

    internal static bool RequiresTlsCertificateRevocationCheck(
        CliDeploymentMode mode)
    {
        return mode switch
        {
            CliDeploymentMode.Production => true,
            CliDeploymentMode.DisposableTest => false,
            CliDeploymentMode.RetainedLab => false,
            _ => throw new InvalidDataException(
                "Client deployment mode is invalid."),
        };
    }

    internal static bool ValidateServerCertificate(
        X509Certificate2? certificate,
        SslPolicyErrors errors,
        CliConfiguration configuration)
    {
        if (certificate is null
            || errors is not SslPolicyErrors.None)
        {
            return false;
        }

        try
        {
            return FixedDigestEquals(
                    CertificateIdentity
                        .ComputeCertificateSha256(
                            certificate),
                    configuration
                        .ServerCertificateSha256)
                && FixedDigestEquals(
                    CertificateIdentity
                        .ComputeSubjectPublicKeyInfoSha256(
                            certificate),
                    configuration.ServerSpkiSha256);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static bool FixedDigestEquals(
        string left,
        string right)
    {
        return left.Length is 64
            && right.Length is 64
            && CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(left),
                Convert.FromHexString(right));
    }

    private static string RequestPath(Guid requestId)
    {
        if (requestId == Guid.Empty)
        {
            throw new ArgumentException(
                "Request identifier is invalid.",
                nameof(requestId));
        }

        return string.Create(
            CultureInfo.InvariantCulture,
            $"v1/requests/{requestId:D}");
    }

    private static bool IsSafeCode(string value)
    {
        return value.Length is > 0 and <= 64
            && char.IsAsciiLetterOrDigit(value[0])
            && value.All(character =>
                char.IsAsciiLetterOrDigit(character)
                || character is '-' or '_' or '.');
    }

    [JsonUnmappedMemberHandling(
        JsonUnmappedMemberHandling.Disallow)]
    private sealed record CliProfilesResponse(
        string Format,
        IReadOnlyList<CliVisibleProfile> Profiles)
    {
        internal const string FormatIdentifier =
            "ArtifactSigningProfilesResponseV2";
    }

    [JsonUnmappedMemberHandling(
        JsonUnmappedMemberHandling.Disallow)]
    private sealed record CliProblem(
        string Code,
        string Message);
}
