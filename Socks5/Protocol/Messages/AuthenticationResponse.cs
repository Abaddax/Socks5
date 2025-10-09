using Abaddax.Socks5.Protocol.Enums;

namespace Abaddax.Socks5.Protocol.Messages
{
    internal record struct AuthenticationResponse
    {
        public AuthenticationMethod AuthenticationMethod { get; set; }
    }
}
