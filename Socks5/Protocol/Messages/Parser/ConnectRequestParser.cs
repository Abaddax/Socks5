using Abaddax.Socks5.Protocol.Enums;
using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace Abaddax.Socks5.Protocol.Messages.Parser
{
    internal sealed class ConnectRequestParser : Socks5ParserBase<ConnectRequest>
    {
        public static ConnectRequestParser Shared { get; } = new();

        public override int GetMessageSize(ConnectRequest message)
        {
            ArgumentNullException.ThrowIfNull(message.Address);
            return message.AddressType switch
            {
                AddressType.IPv4 => 10,
                AddressType.DomainName => 7 + message.Address.Length,
                AddressType.IPv6 => 22,
                _ => throw new ArgumentException(nameof(message.AddressType))
            };
        }
        public override int Write(ConnectRequest message, Span<byte> destination)
        {
            var size = GetMessageSize(message);
            ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, size);

            destination[0] = 0x05;
            destination[1] = (byte)message.ConnectMethod;
            destination[2] = 0x00;
            destination[3] = (byte)message.AddressType;

            switch (message.AddressType)
            {
                case AddressType.IPv4:
                {
                    var address = IPAddress.Parse(message.Address);
                    if (!address.TryWriteBytes(destination.Slice(4, 4), out _))
                        throw new Exception("Failed to parse IPv4");
                    BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(8, 2), message.Port);
                    break;
                }
                case AddressType.DomainName:
                {
                    destination[4] = (byte)message.Address.Length;
                    if (!Encoding.UTF8.TryGetBytes(message.Address, destination.Slice(5, message.Address.Length), out _))
                        throw new Exception("Failed to parse domain-name");
                    BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(5 + message.Address.Length, 2), message.Port);
                    break;
                }
                case AddressType.IPv6:
                {
                    var address = IPAddress.Parse(message.Address);
                    if (!address.TryWriteBytes(destination.Slice(4, 16), out _))
                        throw new Exception("Failed to parse IPv6");
                    BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(20, 2), message.Port);
                    break;
                }
                default:
                    throw new ArgumentException("Unknown address-type");
            }
            return size;
        }
        public override async Task<ConnectRequest> ReadAsync(Stream stream, CancellationToken cancellationToken)
        {
            var message = new ConnectRequest();

            var header = new byte[4];
            await stream.ReadExactlyAsync(header, cancellationToken);
            if (header[0] != 0x05)
                throw new ArgumentException("Invalid socks-version");
            message.ConnectMethod = (ConnectMethod)header[1];
            if (header[2] != 0x00)
                throw new ArgumentException("Unknown reserved purpose");
            message.AddressType = (AddressType)header[3];
            switch (message.AddressType)
            {
                case AddressType.IPv4:
                {
                    var packet = new byte[4 + 2];
                    await stream.ReadExactlyAsync(packet, cancellationToken);
                    var address = new IPAddress(packet.AsSpan(0, 4));
                    message.Address = address.ToString();
                    message.Port = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(4, 2));
                    break;
                }
                case AddressType.DomainName:
                {
                    var length = stream.ReadByte();
                    if (length < byte.MinValue || length > byte.MaxValue)
                        throw new EndOfStreamException();
                    var packet = new byte[length + 2];
                    await stream.ReadExactlyAsync(packet, cancellationToken);
                    message.Address = Encoding.UTF8.GetString(packet.AsSpan(0, length));
                    message.Port = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(length, 2));
                    break;
                }
                case AddressType.IPv6:
                {
                    var packet = new byte[16 + 2];
                    await stream.ReadExactlyAsync(packet, cancellationToken);
                    var address = new IPAddress(packet.AsSpan(0, 16));
                    message.Address = address.ToString();
                    message.Port = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(16, 2));
                    break;
                }
                default:
                    throw new ArgumentException("Unknown address-type");
            }
            return message;
        }
    }
}
