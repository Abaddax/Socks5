using Abaddax.Socks5.Protocol.Enums;

namespace Abaddax.Socks5.Protocol.Messages.Parser
{
    internal sealed class AuthenticationRequestParser : Socks5ParserBase<AuthenticationRequest>
    {
        public static AuthenticationRequestParser Shared { get; } = new();

        public override int GetMessageSize(AuthenticationRequest message)
        {
            if (message.AuthenticationMethods == null)
                throw new ArgumentNullException(nameof(message.AuthenticationMethods));

            return 2 + message.AuthenticationMethods.Length;
        }
        public override int Write(AuthenticationRequest message, Span<byte> destination)
        {
            var size = GetMessageSize(message);
            if (destination.Length < size)
                throw new ArgumentOutOfRangeException(nameof(destination));

            destination[0] = 0x05;
            destination[1] = (byte)message.AuthenticationMethods.Length;
            for (int i = 0; i < message.AuthenticationMethods.Length; i++)
            {
                destination[i + 2] = (byte)message.AuthenticationMethods[i];
            }
            return size;
        }
        public override async Task<AuthenticationRequest> ReadAsync(Stream stream, CancellationToken cancellationToken)
        {
            var message = new AuthenticationRequest();

            var header = new byte[2];
            await stream.ReadExactlyAsync(header, cancellationToken);
            if (header[0] != 0x05)
                throw new ArgumentException("Invalid socks-version");
            var methodsCount = header[1];

            var methods = new byte[methodsCount];
            await stream.ReadExactlyAsync(methods, cancellationToken);

            message.AuthenticationMethods = new AuthenticationMethod[methodsCount];
            for (int i = 0; i < methodsCount; i++)
            {
                message.AuthenticationMethods[i] = (AuthenticationMethod)methods[i];
            }
            return message;
        }
    }
}
