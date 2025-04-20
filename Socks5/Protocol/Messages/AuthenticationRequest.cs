using Abaddax.Socks5.Protocol.Enums;

namespace Abaddax.Socks5.Protocol.Messages
{
    internal struct AuthenticationRequest
    {
        public AuthenticationMethod[] AuthenticationMethods;
    }
}
