using Abaddax.Socks5.Protocol.Enums;
using System.Collections;

namespace Abaddax.Socks5.Authentication
{
    internal sealed class AuthenticationHandlerContainer : IAuthenticationHandler, IEnumerable<IAuthenticationHandler>
    {
        private readonly List<IAuthenticationHandler> _authenticationHandler = new();

        public void Add(IAuthenticationHandler authenticationHandler)
        {
            _authenticationHandler.Add(authenticationHandler ?? throw new ArgumentNullException(nameof(authenticationHandler)));
        }

        #region IAuthenticationHandler
        IEnumerable<AuthenticationMethod> IAuthenticationHandler.SupportedMethods
            => _authenticationHandler.SelectMany(x => x.SupportedMethods);
        Task<AuthenticationMethod?> IAuthenticationHandler.SelectAuthenticationMethodAsync(IEnumerable<AuthenticationMethod> methods, CancellationToken cancellationToken)
        {
            var handler = _authenticationHandler.FirstOrDefault(x => x.SupportedMethods.Intersect(methods).Any());
            if (handler == null)
                return Task.FromResult<AuthenticationMethod?>(null);
            return handler.SelectAuthenticationMethodAsync(methods, cancellationToken);
        }
        Task<Stream> IAuthenticationHandler.AuthenticationHandlerAsync(Stream stream, AuthenticationMethod method, CancellationToken cancellationToken)
        {
            var handler = _authenticationHandler.First(x => x.SupportedMethods.Contains(method));
            return handler.AuthenticationHandlerAsync(stream, method, cancellationToken);
        }
        #endregion

        #region  IEnumerable<IAuthenticationHandler>
        public IEnumerator<IAuthenticationHandler> GetEnumerator() => _authenticationHandler.GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator() => _authenticationHandler.GetEnumerator();
        #endregion
    }
}
