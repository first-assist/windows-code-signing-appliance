using System.Text;

namespace ArtifactSigning.Worker;

public static class WorkerNotificationProtocol
{
    public const int RequestIdMessageBytes = 36;

    public static byte[] Encode(Guid requestId)
    {
        if (requestId == Guid.Empty)
        {
            throw new ArgumentException(
                "Request identifier must not be empty.",
                nameof(requestId));
        }

        return Encoding.ASCII.GetBytes(requestId.ToString("D"));
    }

    public static bool TryDecode(
        ReadOnlySpan<byte> message,
        out Guid requestId)
    {
        requestId = Guid.Empty;
        if (message.Length != RequestIdMessageBytes)
        {
            return false;
        }

        Span<char> characters = stackalloc char[RequestIdMessageBytes];
        for (int index = 0; index < message.Length; index++)
        {
            byte value = message[index];
            bool isCanonicalCharacter =
                value is >= (byte)'0' and <= (byte)'9'
                    or >= (byte)'a' and <= (byte)'f'
                    or (byte)'-';
            if (!isCanonicalCharacter)
            {
                return false;
            }

            characters[index] = (char)value;
        }

        return Guid.TryParseExact(characters, "D", out requestId)
            && requestId != Guid.Empty
            && string.Equals(
                requestId.ToString("D"),
                Encoding.ASCII.GetString(message),
                StringComparison.Ordinal);
    }
}
