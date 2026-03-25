using Abaddax.Socks5.Protocol;
using Abaddax.Socks5.Protocol.Enums;
using Abaddax.Socks5.Protocol.Messages;
using Abaddax.Socks5.Protocol.Messages.Parser;
using Abaddax.Utilities;
using Abaddax.Utilities.Network;

namespace Abaddax.Socks5
{
    public sealed class Socks5ServerProtocol : IDisposable
    {
        private Stream _stream;
        private Stream? _remoteStream;
        private StreamProxy? _proxy;
        private bool _disposedValue;

        public Socks5ServerProtocol(Stream stream)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));

            ConnectionState = ConnectionState.None;
        }

        public Socks5ServerOptions Options { get; init; } = new Socks5ServerOptions();

        public ConnectionState ConnectionState
        {
            get;
            private set
            {
                if (field == value)
                    return;
                field = value;
                Options.ConnectionStateObserver?.OnNext(value);
            }
        }
        public Stream LocalStream
        {
            get
            {
                if (ConnectionState != ConnectionState.Connected)
                    throw new InvalidOperationException("Not jet connected");
                return _stream;
            }
        }
        public Stream? RemoteStream
        {
            get
            {
                if (ConnectionState != ConnectionState.Connected)
                    throw new InvalidOperationException("Not jet connected");
                return _remoteStream;
            }
        }
        public bool IsProxyActive => _proxy?.Active ?? false;

        public SocksEndpoint RemoteEndpoint { get; private set; } = SocksEndpoint.Invalid;
        public SocksEndpoint LocalEndpoint { get; private set; } = SocksEndpoint.Invalid;

        public async Task AcceptAsync(CancellationToken cancellationToken = default)
        {
            if (ConnectionState != ConnectionState.None)
                throw new InvalidOperationException("This method can only be called once");

            Stream handshakeStream = _stream;
            try
            {
                ConnectionState = ConnectionState.Authentication;

                AuthenticationMethod authMethod;
                //Read authentication-request
                {
                    var authRequest = await AuthenticationRequestParser.Shared.ReadAsync(handshakeStream, cancellationToken);
                    authMethod = await Options.AuthenticationHandler.SelectAuthenticationMethodAsync(authRequest.AuthenticationMethods, cancellationToken) ?? AuthenticationMethod.NoAcceptableMethods;
                }
                //Send authentication-response
                {
                    var authResponse = new AuthenticationResponse()
                    {
                        AuthenticationMethod = authMethod
                    };
                    await AuthenticationResponseParser.Shared.WriteAsync(handshakeStream, authResponse, cancellationToken);
                    if (authResponse.AuthenticationMethod == AuthenticationMethod.NoAcceptableMethods)
                        throw new Exception("Invalid authentication method");
                }

                //Handle authentication
                handshakeStream = await Options.AuthenticationHandler.AuthenticationHandlerAsync(handshakeStream, authMethod, cancellationToken);

                ConnectionState = ConnectionState.Connection;

                SocksConnectionResult connectResult;
                //Read connect-request
                {
                    var conRequest = await ConnectRequestParser.Shared.ReadAsync(handshakeStream, cancellationToken);

                    RemoteEndpoint = new SocksEndpoint()
                    {
                        AddressType = conRequest.AddressType,
                        Address = conRequest.Address,
                        Port = conRequest.Port
                    };
                    try
                    {
                        connectResult = await Options.ConnectHandler.Invoke(conRequest.ConnectMethod, RemoteEndpoint, cancellationToken);
                    }
                    catch (Exception)
                    {
                        connectResult = SocksConnectionResult.Failed(ConnectCode.SocksFailure);
                    }
                    _remoteStream = connectResult.Stream;
                    LocalEndpoint = connectResult.LocalEndpoint;
                }
                //Send connect-response
                {
                    var conResponse = new ConnectResponse()
                    {
                        ConnectCode = connectResult.Result,
                        AddressType = connectResult.Success ? LocalEndpoint.AddressType : RemoteEndpoint.AddressType,
                        Address = connectResult.Success ? LocalEndpoint.Address : RemoteEndpoint.Address,
                        Port = connectResult.Success ? LocalEndpoint.Port : RemoteEndpoint.Port,
                    };
                    await ConnectResponseParser.Shared.WriteAsync(handshakeStream, conResponse, cancellationToken);
                    if (!connectResult.Success)
                    {
                        handshakeStream.Close();
                        throw new Exception($"Unable to connect to remote. Code: {connectResult.Result}");
                    }
                }

                _stream = handshakeStream;
                ConnectionState = ConnectionState.Connected;
            }
            catch (Exception ex)
            {
                await handshakeStream.DisposeAsync();
                _stream.Close();
                _remoteStream?.Close();
                ConnectionState = ConnectionState.Disconnected;
                Options.ConnectionStateObserver?.OnError(ex);
                throw;
            }
        }

        public async Task ProxyAsync(CancellationToken cancellationToken, bool leaveOpen = false)
        {
            if (ConnectionState != ConnectionState.Connected)
                throw new InvalidOperationException("No client connected, accept the connection first");
            if (_remoteStream == null)
                throw new InvalidOperationException("No remote-stream to proxy");
            if (IsProxyActive)
                throw new InvalidOperationException("Proxy is already running");
            _proxy?.Dispose();
            _proxy = new StreamProxy(_stream, _remoteStream, leaveStream1Open: leaveOpen, leaveStream2Open: leaveOpen);
            await _proxy.TunnelAsync(cancellationToken);
            if (!leaveOpen)
            {
                _remoteStream.Close();
                _stream.Close();
                ConnectionState = ConnectionState.Disconnected;
            }
        }

        public async Task DisconnectAsync()
        {
            if (_remoteStream != null)
                await _remoteStream.DisposeAsync();
            if (_stream != null)
                await _stream.DisposeAsync();
        }

        #region IDisposable
        private void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    _remoteStream?.Dispose();
                    _stream?.Dispose();
                    _proxy?.Dispose();
                    SafeExecute.InvokeSafe(() => Options.ConnectionStateObserver?.OnCompleted());
                }
                _disposedValue = true;
            }
        }
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        #endregion

    }
}
