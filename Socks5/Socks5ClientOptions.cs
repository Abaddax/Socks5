using Abaddax.Socks5.Authentication;
using Abaddax.Socks5.Protocol.Enums;

namespace Abaddax.Socks5
{
    public class Socks5ClientOptions
    {
        private IAuthenticationHandler _authenticationHandler = new AuthenticationHandlerContainer();
        private ConnectMethod _connectMethod = ConnectMethod.TCPConnect;

        public IAuthenticationHandler AuthenticationHandler
        {
            get => _authenticationHandler;
            set => _authenticationHandler = value ?? throw new ArgumentNullException(nameof(AuthenticationHandler));
        }
        public ConnectMethod ConnectMethod
        {
            get => _connectMethod;
            set => _connectMethod = value;
        }
    }

    public static class Socks5ClientOptionsBuilder
    {
        public static Socks5ClientOptions WithAuthenticationHandler(this Socks5ClientOptions options, IAuthenticationHandler authenticationHandler)
        {
            if (options == null)
                throw new ArgumentNullException(nameof(options));
            if (authenticationHandler == null)
                throw new ArgumentNullException(nameof(authenticationHandler));

            if (options.AuthenticationHandler == null ||
                options.AuthenticationHandler.GetType() == authenticationHandler.GetType())
            {
                options.AuthenticationHandler = authenticationHandler;
            }
            else if (options.AuthenticationHandler is AuthenticationHandlerContainer container)
            {
                container.Add(authenticationHandler);
            }
            else
            {
                options.AuthenticationHandler = new AuthenticationHandlerContainer()
                {
                    options.AuthenticationHandler,
                    authenticationHandler
                };
            }

            return options;
        }

        public static Socks5ClientOptions WithNoAcceptableAuthentication(this Socks5ClientOptions options)
            => options.WithAuthenticationHandler(new NoAcceptableMethods());
        public static Socks5ClientOptions WithNoAuthenticationRequired(this Socks5ClientOptions options)
            => options.WithAuthenticationHandler(new NoAuthenticationRequired());
        public static Socks5ClientOptions WithUsernamePasswordAuthentication(this Socks5ClientOptions options, string username, string password)
            => options.WithAuthenticationHandler(new UsernamePasswordClient(username, password));
        public static Socks5ClientOptions WithSecureSocketLayerAuthentication(this Socks5ClientOptions options, TlsHandshakeHandler handshakeHandler, byte[]? specificOptions = null)
            => options.WithAuthenticationHandler(new SecureSocketsLayerClient(handshakeHandler, specificOptions));

        public static Socks5ClientOptions WithConnectMethod(this Socks5ClientOptions options, ConnectMethod connectMethod)
        {
            if (options == null)
                throw new ArgumentNullException(nameof(options));
            options.ConnectMethod = connectMethod;
            return options;
        }

    }
}
