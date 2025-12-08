using Abaddax.Socks5.Protocol.Enums;
using System.Net;
using System.Net.Sockets;

namespace Abaddax.Socks5.Protocol
{
    public readonly record struct SocksEndpoint
    {
        public required AddressType AddressType { get; init; }
        public required string Address { get; init; }
        public required ushort Port { get; init; }

        public static SocksEndpoint Invalid { get; } = new SocksEndpoint()
        {
            AddressType = AddressType.Unknown,
            Address = "0.0.0.0",
            Port = 0
        };

        public static explicit operator SocksEndpoint(EndPoint? endPoint)
        {
            return endPoint switch
            {
                IPEndPoint ipEndPoint => new SocksEndpoint()
                {
                    AddressType = ipEndPoint.AddressFamily switch
                    {
                        AddressFamily.InterNetwork => AddressType.IPv4,
                        AddressFamily.InterNetworkV6 => AddressType.IPv6,
                        _ => throw new NotSupportedException($"AddressFamily {ipEndPoint.AddressFamily} is not supported")
                    },
                    Address = ipEndPoint.Address.ToString(),
                    Port = (ushort)ipEndPoint.Port
                },
                null => SocksEndpoint.Invalid,
                _ => throw new NotSupportedException($"EndPoint of type {endPoint.GetType()}")
            };
        }
    }
}
