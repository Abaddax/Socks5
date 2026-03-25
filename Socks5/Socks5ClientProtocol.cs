using Abaddax.Socks5.Protocol;
using Abaddax.Socks5.Protocol.Enums;
using Abaddax.Socks5.Protocol.Messages;
using Abaddax.Socks5.Protocol.Messages.Parser;
using Abaddax.Utilities;

namespace Abaddax.Socks5
{
    public sealed class Socks5ClientProtocol : IDisposable
    {
        private Stream _stream;
        private bool _disposedValue;

        public Socks5ClientProtocol(Stream stream)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));

            ConnectionState = ConnectionState.None;
        }

        public Socks5ClientOptions Options { get; init; } = new Socks5ClientOptions();

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
        public Stream Stream
        {
            get
            {
                if (ConnectionState != ConnectionState.Connected)
                    throw new InvalidOperationException("Not jet connected");
                return _stream;
            }
        }

        public SocksEndpoint RemoteEndpoint { get; private set; } = SocksEndpoint.Invalid;
        public SocksEndpoint LocalEndpoint { get; private set; } = SocksEndpoint.Invalid;

        public Task ConnectAsync(AddressType type, string address, ushort port,
            CancellationToken cancellationToken = default)
        {
            return ConnectAsync(new SocksEndpoint()
            {
                AddressType = type,
                Address = address,
                Port = port
            },
            cancellationToken);
        }
        public async Task ConnectAsync(SocksEndpoint remoteEndpoint,
            CancellationToken cancellationToken = default)
        {
            if (remoteEndpoint.AddressType == AddressType.Unknown)
                throw new ArgumentException($"Endpoint is of type {nameof(AddressType.Unknown)}", nameof(remoteEndpoint));
            if (ConnectionState != ConnectionState.None)
                throw new InvalidOperationException("This method can only be called once");

            Stream handshakeStream = _stream;
            try
            {
                ConnectionState = ConnectionState.Authentication;

                AuthenticationMethod authMethod;
                //Send authentication-request
                {
                    var authRequest = new AuthenticationRequest()
                    {
                        AuthenticationMethods = Options.AuthenticationHandler.SupportedMethods.ToHashSet().ToArray()
                    };
                    await AuthenticationRequestParser.Shared.WriteAsync(handshakeStream, authRequest, cancellationToken);
                }
                //Read authentication-response
                {
                    var authResponse = await AuthenticationResponseParser.Shared.ReadAsync(handshakeStream, cancellationToken);
                    if (authResponse.AuthenticationMethod == AuthenticationMethod.NoAcceptableMethods ||
                       !Options.AuthenticationHandler.SupportedMethods.Any(x => x == authResponse.AuthenticationMethod))
                    {
                        throw new Exception("Invalid authentication method");
                    }
                    authMethod = authResponse.AuthenticationMethod;
                }

                //Handle authentication
                handshakeStream = await Options.AuthenticationHandler.AuthenticationHandlerAsync(handshakeStream, authMethod, cancellationToken);

                ConnectionState = ConnectionState.Connection;

                //Send connect-request
                {
                    var conRequest = new ConnectRequest()
                    {
                        ConnectMethod = Options.ConnectMethod,
                        AddressType = remoteEndpoint.AddressType,
                        Address = remoteEndpoint.Address,
                        Port = remoteEndpoint.Port,
                    };
                    await ConnectRequestParser.Shared.WriteAsync(handshakeStream, conRequest, cancellationToken);
                }
                //Read connect-response
                {
                    var conResponse = await ConnectResponseParser.Shared.ReadAsync(handshakeStream, cancellationToken);
                    if (conResponse.ConnectCode != ConnectCode.Succeeded)
                    {
                        throw new Exception($"Connect failed with code: {conResponse.ConnectCode}");
                    }

                    LocalEndpoint = new SocksEndpoint()
                    {
                        AddressType = conResponse.AddressType,
                        Address = conResponse.Address,
                        Port = conResponse.Port
                    };
                }

                RemoteEndpoint = remoteEndpoint;
                _stream = handshakeStream;
                ConnectionState = ConnectionState.Connected;
            }
            catch (Exception ex)
            {
                await handshakeStream.DisposeAsync();
                _stream.Close();
                ConnectionState = ConnectionState.Disconnected;
                Options.ConnectionStateObserver?.OnError(ex);
                throw;
            }
        }

        public async Task DisconnectAsync()
        {
            if (_stream != null)
                await _stream.DisposeAsync();
            ConnectionState = ConnectionState.Disconnected;
        }

        #region IDisposable
        private void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    _stream?.Dispose();
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
