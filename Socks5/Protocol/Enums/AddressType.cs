namespace Abaddax.Socks5.Protocol.Enums
{
    public enum AddressType : byte
    {
        Unknown = 0x00,
        IPv4 = 0x01,
        DomainName = 0x03,
        IPv6 = 0x04
    }
}
