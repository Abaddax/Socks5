using Abaddax.Utilities.Buffers;
using Abaddax.Utilities.Network;
using Abaddax.Utilities.Threading.Tasks;

namespace Abaddax.Socks5.Protocol.Messages.Parser
{
    internal abstract class Socks5ParserBase<TMessage> : ISpanParser<TMessage>, IStreamParser<TMessage>
        where TMessage : struct
    {
        #region ISpanParser<TMessage>
        public abstract int GetMessageSize(TMessage message);
        public virtual TMessage Read(ReadOnlySpan<byte> packet)
        {
            using var tokenSource = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            using var ms = new MemoryStream();
            ms.Write(packet);
            return ReadAsync(ms, tokenSource.Token).AwaitSync();
        }
        public abstract int Write(TMessage message, Span<byte> destination);
        #endregion

        #region IStreamParser<TMessage>
        public abstract Task<TMessage> ReadAsync(Stream stream, CancellationToken cancellationToken = default);
        public virtual async Task WriteAsync(Stream stream, TMessage message, CancellationToken cancellationToken = default)
        {
            var size = GetMessageSize(message);

            var buffer = new byte[size];

            size = Write(message, buffer);

            await stream.WriteAsync(buffer.AsMemory().Slice(0, size), cancellationToken);
            return;
        }
        #endregion
    }
}
