using Abaddax.Socks5.Authentication;
using Abaddax.Socks5.Protocol.Enums;
using Abaddax.Utilities.IO;
using System.Reactive.Linq;
using System.Reactive.Subjects;
using static Abaddax.Socks5.Helper.Socks5ConnectionLog;

namespace Abaddax.Socks5.Helper
{
    internal sealed class Socks5ConnectionLogHandler : CallbackStream<Stream>,
        IAuthenticationHandler,
        IObserver<ConnectionState>,
        IObservable<Socks5ConnectionLog>
    {
        private readonly ConnectionRole _connectionRole;
        private readonly IAuthenticationHandler _authenticationHandler;
        private readonly IObserver<ConnectionState>? _connectionStateObserver;
        private readonly Subject<Socks5ConnectionLog?> _connectionLog = new();
        private readonly IObservable<Socks5ConnectionLog> _connectionLogObservable;
        private readonly bool _logData;

        private ConnectionState _connectionState = ConnectionState.None;
        private bool _disposedValue;

        private bool ShouldLog()
        {
            return _connectionState switch
            {
                ConnectionState.None => true,
                ConnectionState.Authentication => false, //Do not log authentication
                ConnectionState.Connection => true,
                ConnectionState.Connected => _logData,
                ConnectionState.Disconnected => false,
                _ => false
            };
        }
        private ValueTask<int> OnReadCallbackAsync(Memory<byte> buffer, Stream stream, CancellationToken cancellationToken)
        {
            return new(stream.ReadAsync(buffer, cancellationToken).AsTask().ContinueWith(x =>
            {
                _connectionLog.OnNext(new Socks5ConnectionLog()
                {
                    Role = _connectionRole == ConnectionRole.Server ? ConnectionRole.Client : ConnectionRole.Server,
                    Data = buffer.ToArray()
                });
                return x.Result;
            }, TaskContinuationOptions.NotOnFaulted));
        }
        private ValueTask OnWriteCallbackAsync(ReadOnlyMemory<byte> buffer, Stream stream, CancellationToken cancellationToken)
        {
            if (ShouldLog())
            {
                _connectionLog.OnNext(new Socks5ConnectionLog()
                {
                    Role = _connectionRole == ConnectionRole.Server ? ConnectionRole.Server : ConnectionRole.Client,
                    Data = buffer.ToArray()
                });
            }
            return stream.WriteAsync(buffer, cancellationToken);
        }

        public Socks5ConnectionLogHandler(
            Stream stream,
            IAuthenticationHandler authenticationHandler,
            IObserver<ConnectionState>? connectionStateObserver,
            ConnectionRole role,
            bool logData = false)
            : base(stream,
                  readCallback: (_, _, _) => throw new NotImplementedException(),
                  writeCallback: (_, _, _) => throw new NotImplementedException())
        {
            _readCallbackAsync = (buffer, cancellationToken) => OnReadCallbackAsync(buffer, State, cancellationToken);
            _writeCallbackAsync = (buffer, cancellationToken) => OnWriteCallbackAsync(buffer, State, cancellationToken);

            _authenticationHandler = authenticationHandler ?? throw new ArgumentNullException(nameof(authenticationHandler));
            _connectionStateObserver = connectionStateObserver;

            _connectionRole = role;
            _logData = logData;

            _connectionLogObservable = _connectionLog
                .Synchronize()
                .Timeout(TimeSpan.FromSeconds(5), Observable.Return<Socks5ConnectionLog?>(null))
                .Scan(new { Log = new List<Socks5ConnectionLog>(), ToEmit = Array.Empty<Socks5ConnectionLog>() },
                    (acc, log) =>
                    {
                        //Flush
                        if (log == null)
                        {
                            if (acc.Log.Count == 0)
                                return acc;
                            var toEmit = acc.Log.ToArray();
                            acc.Log.Clear();
                            return new { Log = acc.Log, ToEmit = toEmit };
                        }
                        //Append
                        else if (acc.Log.Count == 0 || acc.Log[^1].Role == log.Value.Role)
                        {
                            acc.Log.Add(log.Value);
                            return new { Log = acc.Log, ToEmit = Array.Empty<Socks5ConnectionLog>() };
                        }
                        //Return
                        else
                        {
                            var toEmit = acc.Log.ToArray();
                            acc.Log.Clear();
                            acc.Log.Add(log.Value);
                            return new { Log = acc.Log, ToEmit = toEmit };
                        }
                    })
                .Where(x => x.ToEmit.Length > 0)
                .Select(batch =>
                {
                    var bufferSize = batch.ToEmit
                        .Select(x => x.Data.Length)
                        .Sum();
                    using (var ms = new MemoryStream(bufferSize))
                    {
                        foreach (var entry in batch.ToEmit)
                        {
                            ms.Write(entry.Data);
                        }
                        return new Socks5ConnectionLog()
                        {
                            Role = batch.ToEmit[0].Role,
                            Data = ms.GetBuffer()
                        };
                    }
                });
        }

        #region IAuthenticationHandler
        public IEnumerable<AuthenticationMethod> SupportedMethods => _authenticationHandler.SupportedMethods;
        public Task<AuthenticationMethod?> SelectAuthenticationMethodAsync(IEnumerable<AuthenticationMethod> methods, CancellationToken cancellationToken)
            => _authenticationHandler.SelectAuthenticationMethodAsync(methods, cancellationToken);
        public async Task<Stream> AuthenticationHandlerAsync(Stream stream, AuthenticationMethod method, CancellationToken cancellationToken)
        {
            if (stream != this)
                throw new InvalidOperationException("Can not perform authentication on a different stream. Please use the same stream for logging and authentication");

            _connectionState = ConnectionState.Authentication;
            var newStream = await _authenticationHandler.AuthenticationHandlerAsync(State, method, cancellationToken);
            UpdateState(newStream);
            _connectionState = ConnectionState.Connection;

            return this;
        }
        #endregion

        #region IObserver<ConnectionState>
        public void OnNext(ConnectionState connectionState)
        {
            if (connectionState == ConnectionState.Connected)
            {
                _connectionState = ConnectionState.Connected;
                //Flush
                _connectionLog.OnNext(null);
            }
            else if (connectionState == ConnectionState.Disconnected &&
                _connectionState != ConnectionState.Disconnected)
            {
                _connectionState = ConnectionState.Disconnected;
                _connectionLog.OnCompleted();
            }
            //Forward
            _connectionStateObserver?.OnNext(connectionState);
        }
        public void OnError(Exception error)
        {
            //Forward
            _connectionStateObserver?.OnError(error);
        }
        public void OnCompleted()
        {
            _connectionLog.OnCompleted();
            //Forward
            _connectionStateObserver?.OnCompleted();
        }
        #endregion

        #region IObservable<Socks5ConnectionLog>
        public IDisposable Subscribe(IObserver<Socks5ConnectionLog> observer)
            => _connectionLogObservable.Subscribe(observer);
        #endregion

        #region Stream
        public override bool CanRead => State.CanRead;
        public override bool CanSeek => State.CanSeek;
        public override bool CanWrite => State.CanWrite;
        public override long Length => State.Length;
        public override long Position
        {
            get => State.Position;
            set => State.Position = value;
        }
        public override void Flush() => State.Flush();
        public override long Seek(long offset, SeekOrigin origin) => State.Seek(offset, origin);
        public override void SetLength(long value) => State.SetLength(value);
        #endregion

        #region IDisposable
        protected override void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    State.Dispose();
                    _connectionLog.Dispose();
                }
                base.Dispose(disposing);
                _disposedValue = true;
            }
        }
        #endregion
    }
}
