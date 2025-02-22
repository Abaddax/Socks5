using Socks5.Protocol;

namespace Socks5.Authentication
{
    internal sealed class NoAuthenticationRequired : IAuthenticationHandler
    {
        public IEnumerable<AuthenticationMethod> SupportedMethods { get; } = [AuthenticationMethod.NoAuthenticationRequired];

        public async Task<AuthenticationMethod?> SelectAuthenticationMethod(IEnumerable<AuthenticationMethod> methods, CancellationToken token)
        {
            if (methods?.Any(x => x == AuthenticationMethod.NoAuthenticationRequired) ?? false)
                return AuthenticationMethod.NoAuthenticationRequired;
            return null;
        }
        public async Task<Stream> AuthenticationHandler(Stream stream, AuthenticationMethod method, CancellationToken token)
        {
            if (method != AuthenticationMethod.NoAuthenticationRequired)
                throw new NotSupportedException();

            //UNTESTED
            return stream;
        }

    }
}
