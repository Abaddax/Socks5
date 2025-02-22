namespace Socks5.Protocol
{
    public enum ConnectMethod : byte
    {
        TCPConnect = 0x01,
        TCPBind = 0x02,
        UDPAssociate = 0x03
    }
}
