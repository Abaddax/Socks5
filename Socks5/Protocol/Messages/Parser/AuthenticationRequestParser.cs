using Abaddax.Socks5.Protocol.Enums;
using Abaddax.Utilities.Buffers;
using Abaddax.Utilities.Network;

namespace Abaddax.Socks5.Protocol.Messages.Parser
{
    internal partial class Socks5Parser :
        IBinaryParser<AuthenticationRequest>,
        IStreamParser<AuthenticationRequest>
    {

        #region IBinaryParser<Socks5AuthenticationRequest>
        AuthenticationRequest IBinaryParser<AuthenticationRequest>.Read(ReadOnlySpan<byte> packet)
        {
            using var ms = new MemoryStream();
            ms.Write(packet);
            return ((IStreamParser<AuthenticationRequest>)this).ReadAsync(ms, default).Result;
        }
        int IBinaryParser<AuthenticationRequest>.GetMessageSize(AuthenticationRequest message)
        {
            if (message.AuthenticationMethods == null)
                throw new ArgumentNullException(nameof(message.AuthenticationMethods));

            return 2 + message.AuthenticationMethods.Length;
        }
        int IBinaryParser<AuthenticationRequest>.Write(AuthenticationRequest message, Span<byte> destination)
        {
            var size = ((IBinaryParser<AuthenticationRequest>)this).GetMessageSize(message);
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
        #endregion

        #region IStreamParser<Socks5AuthenticationRequest>
        async Task<AuthenticationRequest> IStreamParser<AuthenticationRequest>.ReadAsync(Stream stream, CancellationToken token)
        {
            var message = new AuthenticationRequest();

            using var header = BufferPool<byte>.Rent(2);
            await stream.ReadExactlyAsync(header, token);
            if (header[0] != 0x05)
                throw new ArgumentException("Invalid socks-version");
            var methodsCount = header[1];

            using var methods = BufferPool<byte>.Rent(methodsCount);
            await stream.ReadExactlyAsync(methods, token);

            message.AuthenticationMethods = new AuthenticationMethod[methodsCount];
            for (int i = 0; i < methodsCount; i++)
            {
                message.AuthenticationMethods[i] = (AuthenticationMethod)methods[i];
            }
            return message;
        }
        public async Task WriteAsync(Stream stream, AuthenticationRequest message, CancellationToken token)
        {
            var size = ((IBinaryParser<AuthenticationRequest>)this).GetMessageSize(message);

            using var buffer = BufferPool<byte>.Rent(size);

            ((IBinaryParser<AuthenticationRequest>)this).Write(message, buffer);

            await stream.WriteAsync(buffer, token);
            return;
        }
        #endregion

    }
}
