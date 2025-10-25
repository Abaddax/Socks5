using Abaddax.Socks5.Protocol;
using Abaddax.Socks5.Protocol.Enums;
using Abaddax.Socks5.Protocol.Messages;
using Abaddax.Socks5.Protocol.Messages.Parser;
using Abaddax.Utilities.IO;
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

        public SocksEndpoint RemoteEndpoint { get; private set; } = SocksEndpoint.Invalid;
        public SocksEndpoint LocalEndpoint { get; private set; } = SocksEndpoint.Invalid;

        public IEnumerable<Socks5ConnectionLog> ConnectionLog
        {
            get
            {
                if (_connectionLog == null)
                    yield break;

                //Merge split messages if needed
                Socks5ConnectionLog.ConnectionRole? lastRole = null;
                byte[] data = Array.Empty<byte>();
                foreach (var logEntry in _connectionLog)
                {
                    if (lastRole == null)
                    {
                        lastRole = logEntry.Role;
                        data = logEntry.Data;
                    }
                    else if (lastRole != logEntry.Role)
                    {
                        yield return new Socks5ConnectionLog() { Role = lastRole.Value, Data = data };
                        lastRole = logEntry.Role;
                        data = logEntry.Data;
                    }
                    else
                    {
                        data = [.. data, .. logEntry.Data];
                    }
                }
                if (lastRole != null)
                    yield return new Socks5ConnectionLog() { Role = lastRole.Value, Data = data };
            }
        }

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
            if (_state != ClientState.None)
                throw new InvalidOperationException("This method can only be called once");

            try
            {
                var handshakeStream = _stream;
                //Log data while handshake is going on
                if (_connectionLog != null)
                {
                    _connectionLog.Clear();
                    handshakeStream = new CallbackStream(
                        (buffer, cancellationToken) =>
                        {
                            return new(_stream.ReadAsync(buffer, cancellationToken).AsTask().ContinueWith(x =>
                            {
                                if (_state != ClientState.Connected)
                                    _connectionLog.Enqueue(new Socks5ConnectionLog() { Role = Socks5ConnectionLog.ConnectionRole.Server, Data = buffer.ToArray() });
                                return x.Result;
                            }, TaskContinuationOptions.NotOnFaulted));
                        },
                        (buffer, cancellationToken) =>
                        {
                            if (_state != ClientState.Connected)
                                _connectionLog.Enqueue(new Socks5ConnectionLog() { Role = Socks5ConnectionLog.ConnectionRole.Client, Data = buffer.ToArray() });
                            return _stream.WriteAsync(buffer, cancellationToken);
                        });
                }

                _state = ClientState.Authentication;

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
                _stream = await Options.AuthenticationHandler.AuthenticationHandler(/*Do not log authentication!*/_stream, authMethod, cancellationToken);

                //Continue with current stream
                if (_connectionLog == null)
                    handshakeStream = _stream;

                _state = ClientState.Connection;

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
                _state = ClientState.Connected;
            }
            catch (Exception)
            {
                _stream.Close();
                throw;
            }
        }

        public Task DisconnectAsync()
        {
            _stream?.Dispose();
            return Task.CompletedTask;
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
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        #endregion

    }
}
