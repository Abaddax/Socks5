namespace Socks5.Protocol.Messages
{
    internal struct ConnectRequest
    {
        public ConnectMethod ConnectMethod;
        public AddressType AddressType;
        public string Address;
        public int Port;
    }
}
