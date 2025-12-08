namespace Abaddax.Socks5.Protocol.Enums
{
    public enum AuthenticationMethod : byte
    {
        NoAuthenticationRequired = 0x00,
        //GSSAPI = 0x01,
        UsernamePassword = 0x02,
        SecureSocketsLayer = 0x06,
        NoAcceptableMethods = 0xFF,
    }
}
