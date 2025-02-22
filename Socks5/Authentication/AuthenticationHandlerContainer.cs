using Socks5.Protocol;
using System.Collections;

namespace Socks5.Authentication
{
    internal sealed class AuthenticationHandlerContainer : IAuthenticationHandler, IEnumerable<IAuthenticationHandler>
    {
        readonly List<IAuthenticationHandler> _authenticationHandler = new();

        public void Add(IAuthenticationHandler authenticationHandler)
        {
            _authenticationHandler.Add(authenticationHandler ?? throw new ArgumentNullException(nameof(authenticationHandler)));
        }

        #region IAuthenticationHandler
        IEnumerable<AuthenticationMethod> IAuthenticationHandler.SupportedMethods =>
           _authenticationHandler.SelectMany(x => x.SupportedMethods);
        Task<AuthenticationMethod?> IAuthenticationHandler.SelectAuthenticationMethod(IEnumerable<AuthenticationMethod> methods, CancellationToken token)
        {
            var handler = _authenticationHandler.FirstOrDefault(x => x.SupportedMethods.Intersect(methods).Any());
            if (handler == null)
                return Task.FromResult<AuthenticationMethod?>(null);
            return handler.SelectAuthenticationMethod(methods, token);
        }
        Task<Stream> IAuthenticationHandler.AuthenticationHandler(Stream stream, AuthenticationMethod method, CancellationToken token)
        {
            var handler = _authenticationHandler.First(x => x.SupportedMethods.Contains(method));
            return handler.AuthenticationHandler(stream, method, token);
        }
        #endregion

        #region  IEnumerable<IAuthenticationHandler>
        public IEnumerator<IAuthenticationHandler> GetEnumerator() => _authenticationHandler.GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator() => _authenticationHandler.GetEnumerator();
        #endregion
    }
}
