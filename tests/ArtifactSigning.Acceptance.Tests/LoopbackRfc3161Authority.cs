using System.Formats.Asn1;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ArtifactSigning.Acceptance.Tests;

internal sealed class LoopbackRfc3161Authority : IDisposable
{
    private const int MaximumHeaderBytes = 16 * 1024;
    private const int MaximumRequestBytes = 64 * 1024;
    private const string Rfc3161ContentTypeOid = "1.2.840.113549.1.9.16.1.4";
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";
    private const string SigningCertificateV2Oid = "1.2.840.113549.1.9.16.2.47";
    private const string TimestampPolicyOid = "1.3.6.1.4.1.311.9999.3161";

    private readonly TcpListener _listener;
    private readonly X509Certificate2 _timestampCertificate;
    private readonly DateTimeOffset _timestamp;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly Task _serverTask;
    private long _serialNumber;
    private int _requestCount;

    internal LoopbackRfc3161Authority(
        X509Certificate2 timestampCertificate,
        DateTimeOffset timestamp)
    {
        ArgumentNullException.ThrowIfNull(timestampCertificate);
        DateTimeOffset universalTimestamp = timestamp.ToUniversalTime();
        if (universalTimestamp.Ticks % TimeSpan.TicksPerSecond is not 0)
        {
            throw new ArgumentException(
                "Disposable timestamp must have whole-second precision.",
                nameof(timestamp));
        }

        _timestampCertificate = timestampCertificate;
        _timestamp = universalTimestamp;
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start(backlog: 1);
        int port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        Endpoint = new Uri(
            $"http://127.0.0.1:{port.ToString(System.Globalization.CultureInfo.InvariantCulture)}/rfc3161");
        _serverTask = RunAsync(_shutdown.Token);
    }

    internal Uri Endpoint { get; }

    internal int RequestCount => Volatile.Read(ref _requestCount);

    public void Dispose()
    {
        _shutdown.Cancel();
        _listener.Dispose();
        try
        {
            _serverTask.GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
        }
        catch (SocketException) when (_shutdown.IsCancellationRequested)
        {
        }
        finally
        {
            _shutdown.Dispose();
        }
    }

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            using TcpClient client =
                await _listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
            client.NoDelay = true;
            await HandleAsync(client, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task HandleAsync(
        TcpClient client,
        CancellationToken cancellationToken)
    {
        using NetworkStream stream = client.GetStream();
        byte[] headerBytes = await ReadHeadersAsync(stream, cancellationToken).ConfigureAwait(false);
        string headers = Encoding.ASCII.GetString(headerBytes);
        string[] lines = headers.Split(
            "\r\n",
            StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length < 3
            || !string.Equals(
                lines[0],
                "POST /rfc3161 HTTP/1.1",
                StringComparison.Ordinal))
        {
            throw new InvalidDataException();
        }

        int? contentLength = null;
        bool contentTypeAccepted = false;
        foreach (string line in lines.Skip(1))
        {
            int separator = line.IndexOf(':', StringComparison.Ordinal);
            if (separator <= 0)
            {
                throw new InvalidDataException();
            }

            string name = line[..separator];
            string value = line[(separator + 1)..].Trim();
            if (string.Equals(
                    name,
                    "Content-Length",
                    StringComparison.OrdinalIgnoreCase))
            {
                if (contentLength is not null
                    || !int.TryParse(
                        value,
                        System.Globalization.NumberStyles.None,
                        System.Globalization.CultureInfo.InvariantCulture,
                        out int parsedLength)
                    || parsedLength is <= 0 or > MaximumRequestBytes)
                {
                    throw new InvalidDataException();
                }

                contentLength = parsedLength;
            }
            else if (string.Equals(
                         name,
                         "Content-Type",
                         StringComparison.OrdinalIgnoreCase))
            {
                contentTypeAccepted = string.Equals(
                    value,
                    "application/timestamp-query",
                    StringComparison.OrdinalIgnoreCase);
            }
        }

        if (contentLength is null || !contentTypeAccepted)
        {
            throw new InvalidDataException();
        }

        byte[] requestBytes = new byte[contentLength.Value];
        await stream.ReadExactlyAsync(requestBytes, cancellationToken).ConfigureAwait(false);
        byte[] responseBytes = CreateResponse(requestBytes);
        byte[] responseHeaders = Encoding.ASCII.GetBytes(
            string.Create(
                System.Globalization.CultureInfo.InvariantCulture,
                $"HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\nContent-Length: {responseBytes.Length}\r\nConnection: close\r\n\r\n"));
        await stream.WriteAsync(responseHeaders, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(responseBytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        _ = Interlocked.Increment(ref _requestCount);
    }

    private byte[] CreateResponse(byte[] requestBytes)
    {
        if (!Rfc3161TimestampRequest.TryDecode(
                requestBytes,
                out Rfc3161TimestampRequest? request,
                out int bytesConsumed)
            || request is null
            || bytesConsumed != requestBytes.Length
            || request.Version is not 1
            || request.HasExtensions
            || !string.Equals(
                request.HashAlgorithmId.Value,
                Sha256Oid,
                StringComparison.Ordinal)
            || request.GetMessageHash().Length is not SHA256.HashSizeInBytes)
        {
            throw new InvalidDataException();
        }

        byte[] serial =
        [
            checked((byte)Interlocked.Increment(ref _serialNumber)),
        ];
        Rfc3161TimestampTokenInfo tokenInfo = new(
            request.RequestedPolicyId ?? new Oid(TimestampPolicyOid),
            new Oid(Sha256Oid),
            request.GetMessageHash(),
            serial,
            _timestamp,
            accuracyInMicroseconds: null,
            isOrdering: false,
            request.GetNonce(),
            timestampAuthorityName: null,
            extensions: null);
        SignedCms timestampCms = new(
            new ContentInfo(
                new Oid(Rfc3161ContentTypeOid),
                tokenInfo.Encode()),
            detached: false);
        CmsSigner signer = new(
            SubjectIdentifierType.IssuerAndSerialNumber,
            _timestampCertificate)
        {
            DigestAlgorithm = new Oid(Sha256Oid),
            IncludeOption = X509IncludeOption.EndCertOnly,
        };
        signer.SignedAttributes.Add(
            new Pkcs9AttributeObject(
                new Oid(SigningCertificateV2Oid),
                EncodeSigningCertificateV2(_timestampCertificate)));
        timestampCms.ComputeSignature(signer, silent: true);

        AsnWriter response = new(AsnEncodingRules.DER);
        using (response.PushSequence())
        {
            using (response.PushSequence())
            {
                response.WriteInteger(0);
            }

            response.WriteEncodedValue(timestampCms.Encode());
        }

        return response.Encode();
    }

    private static async Task<byte[]> ReadHeadersAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        using MemoryStream headers = new();
        byte[] oneByte = new byte[1];
        uint suffix = 0;
        while (headers.Length < MaximumHeaderBytes)
        {
            int bytesRead = await stream.ReadAsync(oneByte, cancellationToken).ConfigureAwait(false);
            if (bytesRead is 0)
            {
                throw new EndOfStreamException();
            }

            headers.WriteByte(oneByte[0]);
            suffix = (suffix << 8) | oneByte[0];
            if (suffix is 0x0d0a0d0a)
            {
                return headers.ToArray();
            }
        }

        throw new InvalidDataException();
    }

    private static byte[] EncodeSigningCertificateV2(
        X509Certificate2 timestampCertificate)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                using (writer.PushSequence())
                {
                    writer.WriteOctetString(
                        SHA256.HashData(timestampCertificate.RawData));
                }
            }
        }

        return writer.Encode();
    }
}
