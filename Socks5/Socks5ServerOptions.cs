using Abaddax.Socks5.Authentication;
using Abaddax.Socks5.Protocol.Enums;

namespace Abaddax.Socks5
{
    public delegate Task<(ConnectCode Result, Stream? Stream)> ConnectionHandler(ConnectMethod method, AddressType type, string address, int port, CancellationToken cancellationToken);

    public class Socks5ServerOptions
    {
        private IAuthenticationHandler _authenticationHandler = new AuthenticationHandlerContainer();
        private ConnectionHandler _connectHandler = (_, _, _, _, _) => Task.FromResult<(ConnectCode, Stream?)>((ConnectCode.HostUnreachable, null));

        public IAuthenticationHandler AuthenticationHandler
        {
            get => _authenticationHandler;
            set => _authenticationHandler = value ?? throw new ArgumentNullException(nameof(AuthenticationHandler));
        }
        public ConnectionHandler ConnectHandler
        {
            get => _connectHandler;
            set => _connectHandler = value ?? throw new ArgumentNullException(nameof(ConnectHandler));
        }
    }


    public static class Socks5ServerOptionsBuilder
    {
        public static Socks5ServerOptions WithAuthenticationHandler(this Socks5ServerOptions options, IAuthenticationHandler authenticationHandler)
        {
            if (options == null)
                throw new ArgumentNullException(nameof(options));
            if (authenticationHandler == null)
                throw new ArgumentNullException(nameof(authenticationHandler));

            if (options.AuthenticationHandler == null)
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

        public static Socks5ServerOptions WithNoAcceptableAuthentication(this Socks5ServerOptions options)
            => options.WithAuthenticationHandler(new NoAcceptableMethods());
        public static Socks5ServerOptions WithNoAuthenticationRequired(this Socks5ServerOptions options)
            => options.WithAuthenticationHandler(new NoAuthenticationRequired());
        public static Socks5ServerOptions WithUsernamePasswordAuthentication(this Socks5ServerOptions options, UserLoginHandler loginhandler)
            => options.WithAuthenticationHandler(new UsernamePasswordServer(loginhandler));
        public static Socks5ServerOptions WithSecureSocketLayerAuthentication(this Socks5ServerOptions options, TlsHandshakeHandler handshakeHandler, byte[]? specificOptions = null)
            => options.WithAuthenticationHandler(new SecureSocketsLayerServer(handshakeHandler, specificOptions));

        public static Socks5ServerOptions WithConnectionHandler(this Socks5ServerOptions options, ConnectionHandler connectHandler)
        {
            if (options == null)
                throw new ArgumentNullException(nameof(options));
            if (connectHandler == null)
                throw new ArgumentNullException(nameof(connectHandler));
            options.ConnectHandler = connectHandler;
            return options;
        }

    }
}
