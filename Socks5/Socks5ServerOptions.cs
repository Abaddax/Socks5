using Abaddax.Socks5.Authentication;
using Abaddax.Socks5.Protocol;
using Abaddax.Socks5.Protocol.Enums;

namespace Abaddax.Socks5
{
    public delegate Task<SocksConnectionResult> ConnectionHandler(ConnectMethod method, SocksEndpoint endpoint, CancellationToken cancellationToken);

    public class Socks5ServerOptions
    {
        public IAuthenticationHandler AuthenticationHandler
        {
            get;
            set => field = value ?? throw new ArgumentNullException(nameof(AuthenticationHandler));
        } = new AuthenticationHandlerContainer();
        public ConnectionHandler ConnectHandler
        {
            get;
            set => field = value ?? throw new ArgumentNullException(nameof(ConnectHandler));
        } = (_, _, _) => Task.FromResult(SocksConnectionResult.Failed(ConnectCode.HostUnreachable));
    }


    public static class Socks5ServerOptionsBuilder
    {
        public static Socks5ServerOptions WithAuthenticationHandler(this Socks5ServerOptions options, IAuthenticationHandler authenticationHandler)
        {
            ArgumentNullException.ThrowIfNull(options);
            ArgumentNullException.ThrowIfNull(authenticationHandler);

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
            ArgumentNullException.ThrowIfNull(options);
            ArgumentNullException.ThrowIfNull(connectHandler);
            options.ConnectHandler = connectHandler;
            return options;
        }

    }
}
