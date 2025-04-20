using Abaddax.Socks5.Protocol;
using Abaddax.Socks5.Protocol.Enums;
using Abaddax.Socks5.Protocol.Messages;
using Abaddax.Socks5.Protocol.Messages.Parser;
using Abaddax.Utilities.Network;
using System.Collections.Concurrent;

namespace Abaddax.Socks5
{
    public sealed class Socks5ClientProtocol : IDisposable
    {
        private enum ClientState
        {
            None = 0,
            Authentication = 1,
            Connection = 2,
            Connected = 3
        }

        private readonly Socks5Parser _parser = new();
        private readonly ConcurrentQueue<Socks5ConnectionLog>? _connectionLog;

        private Stream _stream;
        private ClientState _state;
        private bool _disposedValue;

        public Socks5ClientProtocol(Stream stream, bool useConnectionLog = false)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));

            if (useConnectionLog)
                _connectionLog = new();
            _state = ClientState.None;
        }

        public Socks5ClientOptions Options { get; init; } = new Socks5ClientOptions();

        public Stream Stream
        {
            get
            {
                if (_state != ClientState.Connected)
                    throw new InvalidOperationException("Not jet connected");
                return _stream;
            }
        }


        public AddressType AddressType { get; private set; } = AddressType.IPv4;
        public string Address { get; private set; } = "0.0.0.0";
        public int Port { get; private set; } = 0;


        public IEnumerable<Socks5ConnectionLog> ConnectionLog => _connectionLog?.ToArray() ?? Array.Empty<Socks5ConnectionLog>();


        public async Task ConnectAsync(AddressType type, string address, int port,
            CancellationToken token = default)
        {
            if (_state != ClientState.None)
                throw new InvalidOperationException("This method can only be called once");

            try
            {
                _connectionLog?.Clear();
                _state = ClientState.Authentication;

                AuthenticationMethod authMethod;
                //Send authentication-request
                {
                    var authRequest = new AuthenticationRequest()
                    {
                        AuthenticationMethods = Options.AuthenticationHandler.SupportedMethods.ToHashSet().ToArray()
                    };
                    await ((IStreamParser<AuthenticationRequest>)_parser).WriteAsync(_stream, authRequest, token);
                }
                //Read authentication-response
                {
                    var authResponse = await ((IStreamParser<AuthenticationResponse>)_parser).ReadAsync(_stream, token);
                    if (authResponse.AuthenticationMethod == AuthenticationMethod.NoAcceptableMethods ||
                       !Options.AuthenticationHandler.SupportedMethods.Any(x => x == authResponse.AuthenticationMethod))
                        throw new Exception("Invalid authentication method");
                    authMethod = authResponse.AuthenticationMethod;
                }

                //Handle authentication
                _stream = await Options.AuthenticationHandler.AuthenticationHandler(_stream, authMethod, token);

                _state = ClientState.Connection;

                int responseSize;
                //Send connect-request
                {
                    var conRequest = new ConnectRequest()
                    {
                        ConnectMethod = Options.ConnectMethod,
                        AddressType = type,
                        Address = address,
                        Port = port
                    };
                    await ((IStreamParser<ConnectRequest>)_parser).WriteAsync(_stream, conRequest, token);
                }
                //Read connect-response
                {
                    var conResponse = await ((IStreamParser<ConnectResponse>)_parser).ReadAsync(_stream, token);
                    if (conResponse.ConnectCode != ConnectCode.Succeeded)
                        throw new Exception($"Connect failed with code: {conResponse.ConnectCode}");
                    if (Options.ValidateReceivedEndpoint &&
                        (conResponse.AddressType != type ||
                        conResponse.Address != address ||
                        conResponse.Port != port))
                        throw new Exception($"Received unknown connection-endpoint {conResponse.AddressType}//{conResponse.Address}:{conResponse.Port}. Expected: {type}//{address}:{port}");
                }

                AddressType = type;
                Address = address;
                Port = port;

                _state = ClientState.Connected;
            }
            catch (Exception ex)
            {
                _stream.Close();
                throw;
            }
        }

        public async Task DisconnectAsync()
        {
            _stream?.Dispose();
        }

        #region IDisposable
        private void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    _stream?.Dispose();
                }
                _disposedValue = true;
            }
        }
        ~Socks5ClientProtocol()
        {
            Dispose(false);
        }
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        #endregion

    }
}
