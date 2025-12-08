using Abaddax.Socks5.Protocol.Enums;

namespace Abaddax.Socks5.Protocol.Messages.Parser
{
    internal sealed class AuthenticationResponseParser : Socks5ParserBase<AuthenticationResponse>
    {
        public static AuthenticationResponseParser Shared { get; } = new();

        public override int GetMessageSize(AuthenticationResponse message)
        {
            return 2;
        }
        public override int Write(AuthenticationResponse message, Span<byte> destination)
        {
            var size = GetMessageSize(message);
            ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, size);

            destination[0] = 0x05;
            destination[1] = (byte)message.AuthenticationMethod;

            return size;
        }
        public override async Task<AuthenticationResponse> ReadAsync(Stream stream, CancellationToken cancellationToken)
        {
            var message = new AuthenticationResponse();

            var header = new byte[2];
            await stream.ReadExactlyAsync(header, cancellationToken);
            if (header[0] != 0x05)
                throw new ArgumentException("Invalid socks-version");

            message.AuthenticationMethod = (AuthenticationMethod)header[1];
            return message;
        }
    }
}
