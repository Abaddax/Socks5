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

        public AddressType AddressType { get; private set; } = AddressType.IPv4;
        public string Address { get; private set; } = "0.0.0.0";
        public int Port { get; private set; } = 0;


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
                    handshakeStream = new CallbackStream(
                        (buffer, cancellationToken) =>
                        {
                            return new(_stream.ReadAsync(buffer, cancellationToken).AsTask().ContinueWith(x =>
                            {
                                if (_state != ServerState.Connected)
                                    _connectionLog.Enqueue(new Socks5ConnectionLog() { Role = Socks5ConnectionLog.ConnectionRole.Client, Data = buffer.ToArray() });
                                return x.Result;
                            }, TaskContinuationOptions.NotOnFaulted));
                        },
                        (buffer, cancellationToken) =>
                        {
                            if (_state != ServerState.Connected)
                                _connectionLog.Enqueue(new Socks5ConnectionLog() { Role = Socks5ConnectionLog.ConnectionRole.Server, Data = buffer.ToArray() });
                            return _stream.WriteAsync(buffer, cancellationToken);
                        });
                }

                _state = ServerState.Authentication;

                AuthenticationMethod authMethod;
                //Read authentication-request
                {
                    var authRequest = await AuthenticationRequestParser.Shared.ReadAsync(handshakeStream, cancellationToken);
                    authMethod = await Options.AuthenticationHandler.SelectAuthenticationMethod(authRequest.AuthenticationMethods, cancellationToken) ?? AuthenticationMethod.NoAcceptableMethods;
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
                _stream = await Options.AuthenticationHandler.AuthenticationHandler(/*Do not log authentication!*/_stream, authMethod, cancellationToken);

                //Continue with current stream
                if (_connectionLog == null)
                    handshakeStream = _stream;

                _state = ServerState.Connection;

                ConnectCode code;
                //Read connect-request
                {
                    var conRequest = await ConnectRequestParser.Shared.ReadAsync(handshakeStream, cancellationToken);

                    AddressType = conRequest.AddressType;
                    Address = conRequest.Address;
                    Port = conRequest.Port;
                    try
                    {
                        (code, _remoteStream) = await Options.ConnectHandler.Invoke(conRequest.ConnectMethod, conRequest.AddressType, conRequest.Address, conRequest.Port, cancellationToken);
                    }
                    catch (Exception ex)
                    {
                        code = ConnectCode.SocksFailure;
                        _remoteStream = null;
                    }
                }
                //Send connect-response
                {
                    var conResponse = new ConnectResponse()
                    {
                        ConnectCode = code,
                        AddressType = AddressType,
                        Address = Address,
                        Port = Port,
                    };
                    await ConnectResponseParser.Shared.WriteAsync(handshakeStream, conResponse, cancellationToken);
                    if (code != ConnectCode.Succeeded)
                    {
                        _stream.Close();
                        throw new Exception($"Unable to connect to remote. Code: {code}");
                    }
                }

                _state = ServerState.Connected;
            }
            catch (Exception)
            {
                _stream.Close();
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

        public Task DisconnectAsync()
        {
            _remoteStream?.Dispose();
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
