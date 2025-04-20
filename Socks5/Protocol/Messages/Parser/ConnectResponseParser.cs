using Abaddax.Socks5.Protocol.Enums;
using Abaddax.Utilities.Buffers;
using Abaddax.Utilities.Network;
using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace Abaddax.Socks5.Protocol.Messages.Parser
{
    internal partial class Socks5Parser :
        IBinaryParser<ConnectResponse>,
        IStreamParser<ConnectResponse>
    {

        #region IBinaryParser<ConnectRequest>
        ConnectResponse IBinaryParser<ConnectResponse>.Read(ReadOnlySpan<byte> packet)
        {
            using var ms = new MemoryStream();
            ms.Write(packet);
            return ((IStreamParser<ConnectResponse>)this).ReadAsync(ms, default).Result;
        }
        int IBinaryParser<ConnectResponse>.GetMessageSize(ConnectResponse message)
        {
            if (message.Address == null)
                throw new ArgumentNullException(nameof(message.Address));
            return message.AddressType switch
            {
                AddressType.IPv4 => 10,
                AddressType.DomainName => 7 + message.Address.Length,
                AddressType.IPv6 => 22,
                _ => throw new ArgumentException(nameof(message.AddressType))
            };
        }
        int IBinaryParser<ConnectResponse>.Write(ConnectResponse message, Span<byte> destination)
        {
            if (message.Address == null)
                throw new ArgumentNullException(nameof(message.Address));

            var size = ((IBinaryParser<ConnectResponse>)this).GetMessageSize(message);
            if (destination.Length < size)
                throw new ArgumentOutOfRangeException(nameof(destination));

            destination[0] = 0x05;
            destination[1] = (byte)message.ConnectCode;
            destination[2] = 0x00;
            destination[3] = (byte)message.AddressType;

            switch (message.AddressType)
            {
                case AddressType.IPv4:
                    {
                        var address = IPAddress.Parse(message.Address);
                        if (!address.TryWriteBytes(destination.Slice(4, 4), out _))
                            throw new Exception("Failed to parse IPv4");
                        BinaryPrimitives.WriteInt16BigEndian(destination.Slice(8, 2), (short)message.Port);
                        break;
                    }
                case AddressType.DomainName:
                    {
                        destination[4] = (byte)message.Address.Length;
                        if (!Encoding.UTF8.TryGetBytes(message.Address, destination.Slice(5, message.Address.Length), out _))
                            throw new Exception("Failed to parse domain-name");
                        BinaryPrimitives.WriteInt16BigEndian(destination.Slice(5 + message.Address.Length, 2), (short)message.Port);
                        break;
                    }
                case AddressType.IPv6:
                    {
                        var address = IPAddress.Parse(message.Address);
                        if (!address.TryWriteBytes(destination.Slice(4, 16), out _))
                            throw new Exception("Failed to parse IPv6");
                        BinaryPrimitives.WriteInt16BigEndian(destination.Slice(20, 2), (short)message.Port);
                        break;
                    }
                default:
                    throw new ArgumentException("Unknown address-type");
            }
            return size;
        }
        #endregion

        #region IStreamParser<ConnectRequest>
        async Task<ConnectResponse> IStreamParser<ConnectResponse>.ReadAsync(Stream stream, CancellationToken token)
        {
            var message = new ConnectResponse();

            using var header = BufferPool<byte>.Rent(4);
            await stream.ReadExactlyAsync(header, token);
            if (header[0] != 0x05)
                throw new ArgumentException("Invalid socks-version");
            message.ConnectCode = (ConnectCode)header[1];
            if (header[2] != 0x00)
                throw new ArgumentException("Unknown reserved purpose");
            message.AddressType = (AddressType)header[3];
            switch (message.AddressType)
            {
                case AddressType.IPv4:
                    {
                        using var packet = BufferPool<byte>.Rent(4 + 2);
                        await stream.ReadExactlyAsync(packet, token);
                        var address = new IPAddress(packet.Span.Slice(0, 4));
                        message.Address = address.ToString();
                        message.Port = BinaryPrimitives.ReadInt16BigEndian(packet.Span.Slice(4, 2));
                        break;
                    }
                case AddressType.DomainName:
                    {
                        var length = stream.ReadByte();
                        if (length < byte.MinValue || length > byte.MaxValue)
                            throw new EndOfStreamException();
                        using var packet = BufferPool<byte>.Rent(length + 2);
                        await stream.ReadExactlyAsync(packet, token);
                        message.Address = Encoding.UTF8.GetString(packet.Span.Slice(0, length));
                        message.Port = BinaryPrimitives.ReadInt16BigEndian(packet.Span.Slice(length, 2));
                        break;
                    }
                case AddressType.IPv6:
                    {
                        using var packet = BufferPool<byte>.Rent(16 + 2);
                        await stream.ReadExactlyAsync(packet, token);
                        var address = new IPAddress(packet.Span.Slice(0, 16));
                        message.Address = address.ToString();
                        message.Port = BinaryPrimitives.ReadInt16BigEndian(packet.Span.Slice(16, 2));
                        break;
                    }
                default:
                    throw new ArgumentException("Unknown address-type");
            }
            return message;
        }
        async Task IStreamParser<ConnectResponse>.WriteAsync(Stream stream, ConnectResponse message, CancellationToken token)
        {
            var size = ((IBinaryParser<ConnectResponse>)this).GetMessageSize(message);

            using var buffer = BufferPool<byte>.Rent(size);

            ((IBinaryParser<ConnectResponse>)this).Write(message, buffer);

            await stream.WriteAsync(buffer, token);
            return;
        }
        #endregion

    }
}
