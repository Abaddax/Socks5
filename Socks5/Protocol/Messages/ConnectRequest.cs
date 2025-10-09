using Abaddax.Socks5.Protocol.Enums;

namespace Abaddax.Socks5.Protocol.Messages
{
    internal record struct ConnectRequest
    {
        public ConnectMethod ConnectMethod { get; set; }
        public AddressType AddressType { get; set; }
        public string Address { get; set; }
        public ushort Port { get; set; }
    }
}
