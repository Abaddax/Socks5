namespace Abaddax.Socks5.Protocol
{
    public struct Socks5ConnectionLog
    {
        public enum ConnectionRole
        {
            Server = 0,
            Client = 1
        }
        public ConnectionRole Role { get; set; }
        public byte[] Data { get; set; }
    }
}
