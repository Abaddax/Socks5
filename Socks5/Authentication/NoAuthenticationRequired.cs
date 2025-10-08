using Abaddax.Socks5.Protocol.Enums;

namespace Abaddax.Socks5.Authentication
{
    internal sealed class NoAuthenticationRequired : IAuthenticationHandler
    {
        public IEnumerable<AuthenticationMethod> SupportedMethods { get; } = [AuthenticationMethod.NoAuthenticationRequired];

        public Task<AuthenticationMethod?> SelectAuthenticationMethod(IEnumerable<AuthenticationMethod> methods, CancellationToken cancellationToken)
        {
            if (methods?.Any(x => x == AuthenticationMethod.NoAuthenticationRequired) ?? false)
                return Task.FromResult<AuthenticationMethod?>(AuthenticationMethod.NoAuthenticationRequired);
            return Task.FromResult<AuthenticationMethod?>(null);
        }
        public Task<Stream> AuthenticationHandler(Stream stream, AuthenticationMethod method, CancellationToken cancellationToken)
        {
            if (method != AuthenticationMethod.NoAuthenticationRequired)
                throw new NotSupportedException();

            //UNTESTED
            return Task.FromResult(stream);
        }

    }
}
