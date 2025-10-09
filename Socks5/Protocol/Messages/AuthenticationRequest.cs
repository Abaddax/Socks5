using Abaddax.Socks5.Protocol.Enums;

namespace Abaddax.Socks5.Protocol.Messages
{
    internal record struct AuthenticationRequest
    {
        public AuthenticationMethod[] AuthenticationMethods { get; set; }
    }
}
