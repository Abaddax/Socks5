namespace Abaddax.Socks5.Protocol
{
    public readonly record struct Socks5ConnectionLog
    {
        public enum ConnectionRole
        {
            Server = 0,
            Client = 1
        }
        public required ConnectionRole Role { get; init; }
        public required byte[] Data { get; init; }
    }
}
