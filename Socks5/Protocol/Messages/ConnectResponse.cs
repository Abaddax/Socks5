using Abaddax.Socks5.Protocol.Enums;

namespace Abaddax.Socks5.Protocol.Messages
{
    internal struct ConnectResponse
    {
        public ConnectCode ConnectCode;
        public AddressType AddressType;
        public string Address;
        public int Port;
    }
}
