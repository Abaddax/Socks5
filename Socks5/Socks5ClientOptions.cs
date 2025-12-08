using Abaddax.Socks5.Authentication;
using Abaddax.Socks5.Protocol.Enums;

namespace Abaddax.Socks5
{
    public class Socks5ClientOptions
    {
        private IAuthenticationHandler _authenticationHandler = new AuthenticationHandlerContainer();
        public IAuthenticationHandler AuthenticationHandler
        {
            get => _authenticationHandler;
            set => _authenticationHandler = value ?? throw new ArgumentNullException(nameof(AuthenticationHandler));
        }
        public ConnectMethod ConnectMethod { get; set; } = ConnectMethod.TCPConnect;
    }

    public static class Socks5ClientOptionsBuilder
    {
        public static Socks5ClientOptions WithAuthenticationHandler(this Socks5ClientOptions options, IAuthenticationHandler authenticationHandler)
        {
            ArgumentNullException.ThrowIfNull(options);
            ArgumentNullException.ThrowIfNull(authenticationHandler);

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
            ArgumentNullException.ThrowIfNull(options);
            options.ConnectMethod = connectMethod;
            return options;
        }

    }
}
