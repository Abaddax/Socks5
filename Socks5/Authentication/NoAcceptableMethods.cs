using Abaddax.Socks5.Protocol.Enums;

namespace Abaddax.Socks5.Authentication
{
    internal sealed class NoAcceptableMethods : IAuthenticationHandler
    {
        public IEnumerable<AuthenticationMethod> SupportedMethods { get; } = [AuthenticationMethod.NoAcceptableMethods];

        public async Task<AuthenticationMethod?> SelectAuthenticationMethod(IEnumerable<AuthenticationMethod> methods, CancellationToken token)
        {
            return AuthenticationMethod.NoAcceptableMethods;
        }
        public async Task<Stream> AuthenticationHandler(Stream stream, AuthenticationMethod method, CancellationToken token)
        {
            throw new NotSupportedException();
        }
    }
}
