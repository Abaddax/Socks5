using Abaddax.Socks5.Protocol;
using Abaddax.Socks5.Protocol.Enums;
using Abaddax.Socks5.Protocol.Messages;
using Abaddax.Socks5.Protocol.Messages.Parser;
using Abaddax.Utilities.IO;
using Abaddax.Utilities.Network;
using System.Collections.Concurrent;

namespace Abaddax.Socks5
{
    public sealed class Socks5ServerProtocol : IDisposable
    {
        private enum ServerState
        {
            None = 0,
            Authentication = 1,
            Connection = 2,
            Connected = 3
        }

        private readonly ConcurrentQueue<Socks5ConnectionLog>? _connectionLog;

        private Stream _stream;
        private Stream? _remoteStream;
        private ServerState _state;
        private StreamProxy? _proxy;
        private bool _disposedValue;

        public Socks5ServerProtocol(Stream stream, bool useConnectionLog = false)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));

            if (useConnectionLog)
                _connectionLog = new();

            _state = ServerState.None;
        }

        public Socks5ServerOptions Options { get; init; } = new Socks5ServerOptions();


        public Stream LocalStream
        {
            get
            {
                if (_state != ServerState.Connected)
                    throw new InvalidOperationException("Not jet connected");
                return _stream;
            }
        }
        public Stream? RemoteStream
        {
            get
            {
                if (_state != ServerState.Connected)
                    throw new InvalidOperationException("Not jet connected");
                return _remoteStream;
            }
        }
        public bool IsProxyActive => _proxy?.Active ?? false;

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

        public async Task AcceptAsync(CancellationToken cancellationToken = default)
        {
            if (_state != ServerState.None)
                throw new InvalidOperationException("This method can only be called once");

            try
            {
                var handshakeStream = _stream;
                //Log data while handshake is going on
                if (_connectionLog != null)
                {
                    _connectionLog.Clear();
#pragma warning disable CA2000 //Ownership transfer
                    handshakeStream = new CallbackStream<Stream>(handshakeStream,
                        (buffer, stream, cancellationToken) =>
                        {
                            return new(stream.ReadAsync(buffer, cancellationToken).AsTask().ContinueWith(x =>
                            {
                                if (_state != ServerState.Connected)
                                    _connectionLog.Enqueue(new Socks5ConnectionLog() { Role = Socks5ConnectionLog.ConnectionRole.Client, Data = buffer.ToArray() });
                                return x.Result;
                            }, TaskContinuationOptions.NotOnFaulted));
                        },
                        (buffer, stream, cancellationToken) =>
                        {
                            if (_state != ServerState.Connected)
                                _connectionLog.Enqueue(new Socks5ConnectionLog() { Role = Socks5ConnectionLog.ConnectionRole.Server, Data = buffer.ToArray() });
                            return stream.WriteAsync(buffer, cancellationToken);
                        });
#pragma warning restore CA2000
                }

                _state = ServerState.Authentication;

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
                _stream = await Options.AuthenticationHandler.AuthenticationHandlerAsync(/*Do not log authentication!*/_stream, authMethod, cancellationToken);

                //Continue with current stream
                if (_connectionLog != null &&
                    handshakeStream is CallbackStream<Stream> callbackStream)
                {
                    callbackStream.UpdateState(_stream);
                }
                else
                {
                    handshakeStream = _stream;
                }

                _state = ServerState.Connection;

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
                        _stream.Close();
                        throw new Exception($"Unable to connect to remote. Code: {connectResult.Result}");
                    }
                }

                _state = ServerState.Connected;
            }
            catch (Exception)
            {
                _stream.Close();
                _remoteStream?.Close();
                throw;
            }
        }

        public async Task ProxyAsync(CancellationToken cancellationToken, bool leaveOpen = false)
        {
            if (_state != ServerState.Connected)
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
                _state = ServerState.None;
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
