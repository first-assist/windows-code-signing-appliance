using System.Collections.Frozen;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ArtifactSigning.TimestampRelay;

public enum TimestampRelayDeploymentMode
{
    Production,
    DisposableTest,
}

public sealed class TimestampRelayConfiguration
{
    public const string FormatIdentifier =
        "ArtifactSigningTimestampRelayConfigurationV1";
    public const string InstalledConfigurationPath =
        "/etc/artifact-signing/timestamp-relay.json";
    public const int MaximumConfigurationBytes =
        64 * 1024;

    private static readonly JsonSerializerOptions
        SerializerOptions = new()
        {
            AllowDuplicateProperties = false,
            AllowTrailingCommas = false,
            MaxDepth = 8,
            PropertyNameCaseInsensitive = false,
            ReadCommentHandling =
                JsonCommentHandling.Disallow,
            UnmappedMemberHandling =
                JsonUnmappedMemberHandling.Disallow,
        };

    private TimestampRelayConfiguration(
        TimestampRelayDeploymentMode mode,
        IPAddress bindAddress,
        int bindPort,
        IReadOnlySet<IPAddress> allowedClientAddresses,
        Uri upstreamUrl,
        IReadOnlyList<IPAddress> upstreamAddresses,
        TimeSpan connectTimeout,
        TimeSpan totalTimeout,
        int requestsPerMinute)
    {
        Mode = mode;
        BindAddress = bindAddress;
        BindPort = bindPort;
        AllowedClientAddresses =
            allowedClientAddresses;
        UpstreamUrl = upstreamUrl;
        UpstreamAddresses = upstreamAddresses;
        ConnectTimeout = connectTimeout;
        TotalTimeout = totalTimeout;
        RequestsPerMinute = requestsPerMinute;
    }

    public TimestampRelayDeploymentMode Mode { get; }

    public IPAddress BindAddress { get; }

    public int BindPort { get; }

    public IReadOnlySet<IPAddress>
        AllowedClientAddresses
    { get; }

    public Uri UpstreamUrl { get; }

    public IReadOnlyList<IPAddress>
        UpstreamAddresses
    { get; }

    public TimeSpan ConnectTimeout { get; }

    public TimeSpan TotalTimeout { get; }

    public int RequestsPerMinute { get; }

    public static TimestampRelayConfiguration LoadInstalled()
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException(
                "The timestamp relay is a Linux deployment unit.");
        }

        return LoadProtected(InstalledConfigurationPath);
    }

    internal static TimestampRelayConfiguration
        LoadProtected(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        byte[] before =
            TimestampRelayFileSecurity.ReadOwnerOnly(
                path,
                MaximumConfigurationBytes);
        TimestampRelayConfiguration configuration =
            Parse(before);
        byte[] after =
            TimestampRelayFileSecurity.ReadOwnerOnly(
                path,
                MaximumConfigurationBytes);
        if (!before.AsSpan().SequenceEqual(after))
        {
            throw new InvalidDataException(
                "Timestamp relay configuration changed while loading.");
        }

        return configuration;
    }

    public static TimestampRelayConfiguration Parse(
        ReadOnlySpan<byte> json)
    {
        if (json.IsEmpty
            || json.Length > MaximumConfigurationBytes)
        {
            throw InvalidConfiguration();
        }

        ConfigurationDto dto;
        try
        {
            dto = JsonSerializer.Deserialize<
                    ConfigurationDto>(
                    json,
                    SerializerOptions)
                ?? throw InvalidConfiguration();
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException(
                "Timestamp relay configuration JSON is invalid.",
                exception);
        }

        if (!string.Equals(
                dto.Format,
                FormatIdentifier,
                StringComparison.Ordinal)
            || !Enum.TryParse(
                dto.Mode,
                ignoreCase: false,
                out TimestampRelayDeploymentMode mode)
            || !TryParseCanonicalAddress(
                dto.BindAddress,
                out IPAddress? bindAddress)
            || bindAddress is null
            || !IsPrivateAddress(bindAddress)
            || mode is TimestampRelayDeploymentMode.Production
                && IPAddress.IsLoopback(bindAddress)
            || dto.BindPort is < 1024 or > 65535
            || dto.AllowedClientAddresses is null
                or { Count: 0 or > 16 }
            || dto.UpstreamAddresses is null
                or { Count: 0 or > 4 }
            || !TryParseUpstreamUrl(
                dto.UpstreamUrl,
                mode,
                out Uri? upstreamUrl)
            || upstreamUrl is null
            || dto.ConnectTimeoutSeconds is < 1 or > 5
            || dto.TotalTimeoutSeconds is < 2 or > 15
            || dto.TotalTimeoutSeconds
                <= dto.ConnectTimeoutSeconds
            || dto.RequestsPerMinute is < 1 or > 30)
        {
            throw InvalidConfiguration();
        }

        IPAddress[] clients = ParseAddresses(
            dto.AllowedClientAddresses,
            requirePrivate: true);
        IPAddress[] upstreamAddresses = ParseAddresses(
            dto.UpstreamAddresses,
            requirePrivate: false);
        if (clients.Distinct().Count() != clients.Length
            || upstreamAddresses.Distinct().Count()
                != upstreamAddresses.Length)
        {
            throw InvalidConfiguration();
        }

        return new TimestampRelayConfiguration(
            mode,
            bindAddress,
            dto.BindPort,
            clients.ToFrozenSet(),
            upstreamUrl,
            Array.AsReadOnly(upstreamAddresses),
            TimeSpan.FromSeconds(
                dto.ConnectTimeoutSeconds),
            TimeSpan.FromSeconds(
                dto.TotalTimeoutSeconds),
            dto.RequestsPerMinute);
    }

    private static IPAddress[] ParseAddresses(
        IEnumerable<string> values,
        bool requirePrivate)
    {
        IPAddress[] addresses = values.Select(value =>
        {
            if (!TryParseCanonicalAddress(
                    value,
                    out IPAddress? address)
                || address is null
                || requirePrivate
                    && !IsPrivateAddress(address))
            {
                throw InvalidConfiguration();
            }

            return address;
        }).ToArray();
        return addresses;
    }

    private static bool TryParseCanonicalAddress(
        string? value,
        out IPAddress? address)
    {
        return IPAddress.TryParse(value, out address)
            && address is not null
            && string.Equals(
                value,
                address.ToString(),
                StringComparison.Ordinal);
    }

    private static bool TryParseUpstreamUrl(
        string? value,
        TimestampRelayDeploymentMode mode,
        out Uri? uri)
    {
        return Uri.TryCreate(
                value,
                UriKind.Absolute,
                out uri)
            && uri is not null
            && string.Equals(
                value,
                uri.AbsoluteUri,
                StringComparison.Ordinal)
            && uri.AbsoluteUri.Length <= 512
            && uri.Scheme is "https" or "http"
            && (mode is
                    TimestampRelayDeploymentMode
                        .DisposableTest
                || uri.Scheme == Uri.UriSchemeHttps)
            && !string.IsNullOrWhiteSpace(uri.Host)
            && string.IsNullOrEmpty(uri.UserInfo)
            && string.IsNullOrEmpty(uri.Query)
            && string.IsNullOrEmpty(uri.Fragment)
            && uri.AbsolutePath.Length is > 0 and <= 256
            && !uri.AbsolutePath.Contains(
                "//",
                StringComparison.Ordinal);
    }

    private static bool IsPrivateAddress(
        IPAddress address)
    {
        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        byte[] bytes = address.GetAddressBytes();
        if (address.AddressFamily
            is System.Net.Sockets.AddressFamily
                .InterNetwork)
        {
            return bytes[0] is 10
                || bytes[0] is 172
                    && bytes[1] is >= 16 and <= 31
                || bytes[0] is 192 && bytes[1] is 168;
        }

        return address.AddressFamily
                is System.Net.Sockets.AddressFamily
                    .InterNetworkV6
            && (bytes[0] & 0xfe) == 0xfc;
    }

    private static InvalidDataException
        InvalidConfiguration()
    {
        return new InvalidDataException(
            "Timestamp relay configuration is invalid.");
    }

    private sealed class ConfigurationDto
    {
        public required string Format { get; init; }

        public required string Mode { get; init; }

        public required string BindAddress { get; init; }

        public required int BindPort { get; init; }

        public required IReadOnlyList<string>
            AllowedClientAddresses
        { get; init; }

        public required string UpstreamUrl { get; init; }

        public required IReadOnlyList<string>
            UpstreamAddresses
        { get; init; }

        public required int ConnectTimeoutSeconds
        {
            get;
            init;
        }

        public required int TotalTimeoutSeconds
        {
            get;
            init;
        }

        public required int RequestsPerMinute { get; init; }
    }
}
