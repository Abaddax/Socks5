namespace Abaddax.Socks5.Protocol.Enums
{
    public enum ConnectMethod : byte
    {
        Unknown = 0x00,
        TCPConnect = 0x01,
        TCPBind = 0x02,
        UDPAssociate = 0x03
    }
}
