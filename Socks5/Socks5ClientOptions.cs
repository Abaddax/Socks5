using Abaddax.Socks5.Authentication;
using Abaddax.Socks5.Protocol.Enums;

namespace Abaddax.Socks5
{
    public record class Socks5ClientOptions
    {
        public IAuthenticationHandler AuthenticationHandler
        {
            get;
            set => field = value ?? throw new ArgumentNullException(nameof(AuthenticationHandler));
        } = new AuthenticationHandlerContainer();
        public ConnectMethod ConnectMethod { get; set; } = ConnectMethod.TCPConnect;
        public IObserver<ConnectionState>? ConnectionStateObserver { get; set; }
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

        public static Socks5ClientProtocol CreateSocksClient(this Socks5ClientOptions options, Stream stream)
        {
            ArgumentNullException.ThrowIfNull(options);
            ArgumentNullException.ThrowIfNull(stream);
            //Clone options
            options = options with { };
            return new Socks5ClientProtocol(stream)
            {
                Options = options
            };
        }
    }
}
