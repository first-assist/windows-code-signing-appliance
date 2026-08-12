using System.Formats.Asn1;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Hosting;

namespace ArtifactSigning.DisposableLab;

internal sealed class DisposableTimestampAuthority :
    BackgroundService
{
    private const int MaximumHeaderBytes = 16 * 1024;
    private const int MaximumRequestBytes = 64 * 1024;
    private const string Rfc3161ContentTypeOid =
        "1.2.840.113549.1.9.16.1.4";
    private const string Sha256Oid =
        "2.16.840.1.101.3.4.2.1";
    private const string SigningCertificateV2Oid =
        "1.2.840.113549.1.9.16.2.47";
    private const string TimestampPolicyOid =
        "1.3.6.1.4.1.311.9999.3161";

    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        using X509Certificate2 certificate =
            LoadTimestampCertificate();
        TcpListener listener = new(
            IPAddress.Loopback,
            DisposableLabPaths.TimestampPort);
        try
        {
            listener.Start(backlog: 2);
            while (!stoppingToken.IsCancellationRequested)
            {
                using TcpClient client =
                    await listener.AcceptTcpClientAsync(
                        stoppingToken).ConfigureAwait(false);
                client.NoDelay = true;
                try
                {
                    await HandleAsync(
                        client,
                        certificate,
                        stoppingToken).ConfigureAwait(false);
                }
                catch (Exception exception)
                    when (exception is IOException
                        or CryptographicException
                        or InvalidDataException
                        or SocketException)
                {
                }
            }
        }
        catch (OperationCanceledException)
            when (stoppingToken.IsCancellationRequested)
        {
        }
        finally
        {
            listener.Stop();
        }
    }

    private static async Task HandleAsync(
        TcpClient client,
        X509Certificate2 certificate,
        CancellationToken cancellationToken)
    {
        using NetworkStream stream = client.GetStream();
        byte[] headerBytes = await ReadHeadersAsync(
            stream,
            cancellationToken).ConfigureAwait(false);
        string headers = Encoding.ASCII.GetString(headerBytes);
        string[] lines = headers.Split(
            "\r\n",
            StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length >= 2
            && string.Equals(
                lines[0],
                "GET /health/ready HTTP/1.1",
                StringComparison.Ordinal))
        {
            byte[] readyBody =
                """{"Status":"Ready"}"""u8.ToArray();
            byte[] readyHeaders =
                Encoding.ASCII.GetBytes(
                    string.Create(
                        System.Globalization.CultureInfo.InvariantCulture,
                        $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {readyBody.Length}\r\nConnection: close\r\n\r\n"));
            await stream.WriteAsync(
                readyHeaders,
                cancellationToken).ConfigureAwait(false);
            await stream.WriteAsync(
                readyBody,
                cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(
                cancellationToken).ConfigureAwait(false);
            return;
        }

        if (lines.Length < 3
            || !string.Equals(
                lines[0],
                "POST /timestamp HTTP/1.1",
                StringComparison.Ordinal))
        {
            throw new InvalidDataException();
        }

        int? contentLength = null;
        bool contentTypeAccepted = false;
        foreach (string line in lines.Skip(1))
        {
            int separator = line.IndexOf(
                ':',
                StringComparison.Ordinal);
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
                    || parsedLength is <= 0
                        or > MaximumRequestBytes)
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

        byte[] requestBytes =
            new byte[contentLength.Value];
        await stream.ReadExactlyAsync(
            requestBytes,
            cancellationToken).ConfigureAwait(false);
        byte[] responseBytes = CreateResponse(
            requestBytes,
            certificate);
        byte[] responseHeaders = Encoding.ASCII.GetBytes(
            string.Create(
                System.Globalization.CultureInfo.InvariantCulture,
                $"HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\nContent-Length: {responseBytes.Length}\r\nConnection: close\r\n\r\n"));
        await stream.WriteAsync(
            responseHeaders,
            cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(
            responseBytes,
            cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(
            cancellationToken).ConfigureAwait(false);
    }

    private static byte[] CreateResponse(
        byte[] requestBytes,
        X509Certificate2 certificate)
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
            || request.GetMessageHash().Length
                is not SHA256.HashSizeInBytes)
        {
            throw new InvalidDataException();
        }

        byte[] serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7f;
        DateTimeOffset now = DateTimeOffset.UtcNow;
        now = new DateTimeOffset(
            now.Ticks
            - (now.Ticks % TimeSpan.TicksPerSecond),
            TimeSpan.Zero);
        Rfc3161TimestampTokenInfo tokenInfo = new(
            request.RequestedPolicyId
                ?? new Oid(TimestampPolicyOid),
            new Oid(Sha256Oid),
            request.GetMessageHash(),
            serial,
            now,
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
            certificate)
        {
            DigestAlgorithm = new Oid(Sha256Oid),
            IncludeOption = X509IncludeOption.EndCertOnly,
        };
        signer.SignedAttributes.Add(
            new Pkcs9AttributeObject(
                new Oid(SigningCertificateV2Oid),
                EncodeSigningCertificateV2(certificate)));
        timestampCms.ComputeSignature(
            signer,
            silent: true);

        AsnWriter response = new(
            AsnEncodingRules.DER);
        using (response.PushSequence())
        {
            using (response.PushSequence())
            {
                response.WriteInteger(0);
            }

            response.WriteEncodedValue(
                timestampCms.Encode());
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
            int bytesRead = await stream.ReadAsync(
                oneByte,
                cancellationToken).ConfigureAwait(false);
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
        X509Certificate2 certificate)
    {
        AsnWriter writer = new(
            AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                using (writer.PushSequence())
                {
                    writer.WriteOctetString(
                        SHA256.HashData(
                            certificate.RawData));
                }
            }
        }

        return writer.Encode();
    }

    private static X509Certificate2
        LoadTimestampCertificate()
    {
        byte[] evidenceBytes = File.ReadAllBytes(
            DisposableLabPaths.Evidence);
        DisposableLabEvidence? evidence =
            JsonSerializer.Deserialize<
                DisposableLabEvidence>(
                evidenceBytes,
                DisposableJson.Options);
        if (evidence is null
            || evidence.Format
                != "ArtifactSigningDisposableLabEvidenceV1")
        {
            throw new InvalidDataException();
        }

        using X509Store store = new(
            StoreName.My,
            StoreLocation.LocalMachine);
        store.Open(
            OpenFlags.ReadOnly
            | OpenFlags.OpenExistingOnly);
        X509Certificate2Collection matches =
            store.Certificates.Find(
                X509FindType.FindByThumbprint,
                evidence.Timestamp.Thumbprint,
                validOnly: false);
        X509Certificate2[] exact = matches
            .OfType<X509Certificate2>()
            .Where(item => string.Equals(
                item.Thumbprint,
                evidence.Timestamp.Thumbprint,
                StringComparison.Ordinal))
            .ToArray();
        if (exact.Length is not 1
            || !exact[0].HasPrivateKey)
        {
            foreach (X509Certificate2 item in exact)
            {
                item.Dispose();
            }

            throw new InvalidDataException();
        }

        return exact[0];
    }
}
