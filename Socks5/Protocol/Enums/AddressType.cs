namespace Socks5.Protocol
{
    public enum AddressType : byte
    {
        IPv4 = 0x01,
        DomainName = 0x03,
        IPv6 = 0x04
    }
}
