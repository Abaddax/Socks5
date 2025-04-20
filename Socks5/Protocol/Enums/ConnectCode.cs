namespace Abaddax.Socks5.Protocol.Enums
{
    public enum ConnectCode : byte
    {
        Succeeded = 0x00,
        SocksFailure = 0x01,
        NotAllowedByRuleset = 0x02,
        NetworkUnreachable = 0x03,
        HostUnreachable = 0x04,
        ConnectionRefused = 0x05,
        TtlExpired = 0x06,
        CommandNotSupported = 0x07,
        AddressTypeNotSupported = 0x08
    }
}
