using Abaddax.Socks5.Protocol.Enums;
using Abaddax.Utilities.IO;
using System.Buffers.Binary;

namespace Abaddax.Socks5.Authentication
{
    public delegate Task<Stream> TlsHandshakeHandler(Stream stream, CancellationToken token);

    internal sealed class SecureSocketsLayer : IAuthenticationHandler
    {
        private readonly TlsHandshakeHandler _handshakeHandler;
        private readonly byte[]? _specificOptions;
        private readonly bool _server;

        public IEnumerable<AuthenticationMethod> SupportedMethods { get; } = [AuthenticationMethod.SecureSocketsLayer];

        public SecureSocketsLayer(TlsHandshakeHandler handshakeHandler, byte[]? specificOptions = null, bool server = false)
        {
            _handshakeHandler = handshakeHandler ?? throw new ArgumentNullException(nameof(handshakeHandler));
            _specificOptions = specificOptions;
            _server = server;
        }

        public async Task<AuthenticationMethod?> SelectAuthenticationMethod(IEnumerable<AuthenticationMethod> methods, CancellationToken token)
        {
            if (methods?.Any(x => x == AuthenticationMethod.SecureSocketsLayer) ?? false)
                return AuthenticationMethod.SecureSocketsLayer;
            return null;
        }
        public async Task<Stream> AuthenticationHandler(Stream stream, AuthenticationMethod method, CancellationToken token)
        {
            if (method != AuthenticationMethod.SecureSocketsLayer)
                throw new NotSupportedException();

            //Initial handshake
            var socksStream = new Socks5CryptoStream(stream)
            {
                SubnegotiationVersion = 0x01,
                TLSCommand = Socks5CryptoStream.TlsCommand.InitalHandshake
            };

            stream = await _handshakeHandler.Invoke(socksStream, token);

            //Option negotiation
            if (_specificOptions != null)
            {
                socksStream.TLSCommand = Socks5CryptoStream.TlsCommand.OptionNegotiation;
                if (_server)
                {
                    await stream.ReadExactlyAsync(_specificOptions, token);
                    await stream.WriteAsync(_specificOptions, token);
                }
                else
                {
                    await stream.WriteAsync(_specificOptions, token);
                    await stream.ReadExactlyAsync(_specificOptions, token);
                }
            }

            //Data flow
            socksStream.TLSCommand = Socks5CryptoStream.TlsCommand.DataFlow;

            return stream;
        }

        #region Helper
        private sealed class Socks5CryptoStream : SpanStream
        {
            /// <summary>
            /// https://datatracker.ietf.org/doc/html/draft-ietf-aft-socks-ssl-00
            /// </summary>
            public enum TlsCommand : byte
            {
                InitalHandshake = 0x01,
                OptionNegotiation = 0x02,
                DataFlow = 0x03,
                ClosingHandshake = 0x04,
            }

            private readonly Stream _innerStream;
            private int _pendingBytes = 0;

            public byte SubnegotiationVersion { get; set; } = 1;
            public TlsCommand TLSCommand { get; set; } = TlsCommand.InitalHandshake;
            public Socks5CryptoStream(Stream workStream)
            {
                if (workStream == null)
                    throw new ArgumentNullException(nameof(workStream));
                _innerStream = workStream;
            }

            #region Stream
            public override bool CanRead => _innerStream.CanRead;
            public override bool CanSeek => _innerStream.CanSeek;
            public override bool CanWrite => _innerStream.CanWrite;
            public override long Length => _innerStream.Length;
            public override long Position { get => _innerStream.Position; set => _innerStream.Position = value; }

            public override int Read(Span<byte> buffer)
            {
                Span<byte> header = stackalloc byte[4];
                if (_pendingBytes == 0)
                {
                    //Read next header                        
                    _innerStream.ReadExactly(header);
                    SubnegotiationVersion = header[0];
                    TLSCommand = (TlsCommand)header[1];
                    _pendingBytes = BinaryPrimitives.ReadUInt16BigEndian(header.Slice(2, 2));
                    if (TLSCommand == TlsCommand.ClosingHandshake)
                    {
                        Close();
                        throw new Exception("Connection closed");
                    }
                }

                var read = _innerStream.Read(buffer.Slice(0, Math.Min(buffer.Length, _pendingBytes)));
                if (read <= 0)
                    return -1;
                _pendingBytes -= read;
                return read;
            }
            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
            {
                Span<byte> header = stackalloc byte[4];
                if (_pendingBytes == 0)
                {
                    //Read next header                        
                    _innerStream.ReadExactly(header);
                    SubnegotiationVersion = header[0];
                    TLSCommand = (TlsCommand)header[1];
                    _pendingBytes = BinaryPrimitives.ReadUInt16BigEndian(header.Slice(2, 2));
                    if (TLSCommand == TlsCommand.ClosingHandshake)
                    {
                        Close();
                        throw new Exception("Connection closed");
                    }
                }

                var read = await _innerStream.ReadAsync(buffer.Slice(0, Math.Min(buffer.Length, _pendingBytes)));
                if (read <= 0)
                    return -1;
                _pendingBytes -= read;
                return read;
            }

            public override void Flush() => _innerStream.Flush();
            public override long Seek(long offset, SeekOrigin origin) => _innerStream.Seek(offset, origin);
            public override void SetLength(long value) => _innerStream.SetLength(value);

            public override void Write(ReadOnlySpan<byte> buffer)
            {
                Span<byte> header = stackalloc byte[4];
                int write = buffer.Length;
                int offset = 0;
                while (write > 0)
                {
                    int count = Math.Min(write, short.MaxValue);
                    header[0] = SubnegotiationVersion;
                    header[1] = (byte)TLSCommand;
                    BinaryPrimitives.WriteUInt16BigEndian(header.Slice(2, 2), (ushort)count);
                    _innerStream.Write(header);
                    _innerStream.Write(buffer.Slice(offset, count));
                    write -= count;
                    offset += count;
                }
            }
            public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
            {
                int write = buffer.Length;
                int offset = 0;
                while (write > 0)
                {
                    Span<byte> header = stackalloc byte[4];
                    int count = Math.Min(write, short.MaxValue);
                    header[0] = SubnegotiationVersion;
                    header[1] = (byte)TLSCommand;
                    BinaryPrimitives.WriteUInt16BigEndian(header.Slice(2, 2), (ushort)count);
                    _innerStream.Write(header);
                    await _innerStream.WriteAsync(buffer.Slice(offset, count), cancellationToken);
                    write -= count;
                    offset += count;
                }
            }

            public override void Close()
            {
                try
                {
                    //Send close frame
                    Span<byte> header = stackalloc byte[4];
                    header[0] = SubnegotiationVersion;
                    header[1] = (byte)TlsCommand.ClosingHandshake;
                    header[2] = 0;
                    header[3] = 0;
                    _innerStream.Write(header);
                }
                catch (Exception ex)
                {
                    //Dont care
                }
                _innerStream.Close();
                base.Close();
            }
            protected override void Dispose(bool disposing)
            {
                _innerStream.Dispose();
                base.Dispose(disposing);
            }
            #endregion
        }
        #endregion
    }

    public sealed class SecureSocketsLayerServer : IAuthenticationHandler
    {
        private readonly SecureSocketsLayer _ssl;

        public SecureSocketsLayerServer(TlsHandshakeHandler handshakeHandler, byte[]? specificOptions = null)
        {
            _ssl = new SecureSocketsLayer(handshakeHandler, specificOptions, server: true);
        }

        public IEnumerable<AuthenticationMethod> SupportedMethods =>
            _ssl.SupportedMethods;
        public Task<Stream> AuthenticationHandler(Stream stream, AuthenticationMethod method, CancellationToken token) =>
            _ssl.AuthenticationHandler(stream, method, token);
        public Task<AuthenticationMethod?> SelectAuthenticationMethod(IEnumerable<AuthenticationMethod> methods, CancellationToken token) =>
            _ssl.SelectAuthenticationMethod(methods, token);
    }

    public sealed class SecureSocketsLayerClient : IAuthenticationHandler
    {
        private readonly SecureSocketsLayer _ssl;

        public SecureSocketsLayerClient(TlsHandshakeHandler handshakeHandler, byte[]? specificOptions = null)
        {
            _ssl = new SecureSocketsLayer(handshakeHandler, specificOptions, server: false);
        }

        public IEnumerable<AuthenticationMethod> SupportedMethods =>
            _ssl.SupportedMethods;
        public Task<Stream> AuthenticationHandler(Stream stream, AuthenticationMethod method, CancellationToken token) =>
            _ssl.AuthenticationHandler(stream, method, token);
        public Task<AuthenticationMethod?> SelectAuthenticationMethod(IEnumerable<AuthenticationMethod> methods, CancellationToken token) =>
            _ssl.SelectAuthenticationMethod(methods, token);
    }

}
