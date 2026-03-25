using static Abaddax.Socks5.Helper.Socks5ConnectionLog;

namespace Abaddax.Socks5.Helper
{
    public static class Socks5ConnectionLogExtensions
    {
        public static Socks5ClientProtocol CreateLoggedSocksClient(this Socks5ClientOptions options, Stream stream, out IObservable<Socks5ConnectionLog> connectionLog, bool logData = false)
        {
            ArgumentNullException.ThrowIfNull(options);
            ArgumentNullException.ThrowIfNull(stream);
            var logHandler = new Socks5ConnectionLogHandler(stream, options.AuthenticationHandler, options.ConnectionStateObserver, ConnectionRole.Client, logData: logData);
            try
            {
                options = options with
                {
                    AuthenticationHandler = logHandler,
                    ConnectionStateObserver = logHandler
                };

                var socksClient = options.CreateSocksClient(logHandler);

                connectionLog = logHandler;
                //Successfull -> set 'null' to skip dispose
                logHandler = null;
                return socksClient;
            }
            finally
            {
                logHandler?.Dispose();
            }
        }
        public static Socks5ServerProtocol CreateLoggedSocksServer(this Socks5ServerOptions options, Stream stream, out IObservable<Socks5ConnectionLog> connectionLog, bool logData = false)
        {
            ArgumentNullException.ThrowIfNull(options);
            ArgumentNullException.ThrowIfNull(stream);
            var logHandler = new Socks5ConnectionLogHandler(stream, options.AuthenticationHandler, options.ConnectionStateObserver, ConnectionRole.Server, logData: logData);
            try
            {
                options = options with
                {
                    AuthenticationHandler = logHandler,
                    ConnectionStateObserver = logHandler
                };

                var socksServer = options.CreateSocksServer(logHandler);

                connectionLog = logHandler;
                //Successfull -> set 'null' to skip dispose
                logHandler = null;
                return socksServer;
            }
            finally
            {
                logHandler?.Dispose();
            }
        }
    }
}
