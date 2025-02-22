using Abaddax.Utilities.Buffers;
using Abaddax.Utilities.Network;

namespace Socks5.Protocol.Messages.Parser
{
    internal partial class Socks5Parser :
        IBinaryParser<AuthenticationResponse>,
        IStreamParser<AuthenticationResponse>
    {

        #region IBinaryParser<Socks5AuthenticationResponse>
        AuthenticationResponse IBinaryParser<AuthenticationResponse>.Read(ReadOnlySpan<byte> packet)
        {
            using var ms = new MemoryStream();
            ms.Write(packet);
            return ((IStreamParser<AuthenticationResponse>)this).ReadAsync(ms, default).Result;
        }
        int IBinaryParser<AuthenticationResponse>.GetMessageSize(AuthenticationResponse message)
        {
            return 2;
        }
        int IBinaryParser<AuthenticationResponse>.Write(AuthenticationResponse message, Span<byte> destination)
        {
            var size = ((IBinaryParser<AuthenticationResponse>)this).GetMessageSize(message);
            if (destination.Length < size)
                throw new ArgumentOutOfRangeException(nameof(destination));

            destination[0] = 0x05;
            destination[1] = (byte)message.AuthenticationMethod;

            return size;
        }
        #endregion

        #region IStreamParser<Socks5AuthenticationResponse>
        async Task<AuthenticationResponse> IStreamParser<AuthenticationResponse>.ReadAsync(Stream stream, CancellationToken token)
        {
            var message = new AuthenticationResponse();

            using var header = BufferPool<byte>.Rent(2);
            await stream.ReadExactlyAsync(header, token);
            if (header[0] != 0x05)
                throw new ArgumentException("Invalid socks-version");

            message.AuthenticationMethod = (AuthenticationMethod)header[1];
            return message;
        }
        async Task IStreamParser<AuthenticationResponse>.WriteAsync(Stream stream, AuthenticationResponse message, CancellationToken token)
        {
            var size = ((IBinaryParser<AuthenticationResponse>)this).GetMessageSize(message);

            using var buffer = BufferPool<byte>.Rent(size);

            ((IBinaryParser<AuthenticationResponse>)this).Write(message, buffer);

            await stream.WriteAsync(buffer, token);
            return;
        }
        #endregion

    }
}
