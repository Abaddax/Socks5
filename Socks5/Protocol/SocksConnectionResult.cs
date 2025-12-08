using Abaddax.Socks5.Protocol.Enums;

namespace Abaddax.Socks5.Protocol
{
    public readonly record struct SocksConnectionResult
    {
        public bool Success => Result == ConnectCode.Succeeded;
        /// <summary>
        /// Result of the connect request
        /// </summary>
        public required ConnectCode Result { get; init; }
        /// <summary>
        /// Stream to the requested remote-endpoint
        /// </summary>
        /// <remarks><see langword="null"/> if <see cref="SocksConnectionResult.Result"/> is not <see cref="ConnectCode.Succeeded"/></remarks>
        public required Stream? Stream { get; init; }
        /// <summary>
        /// Local-endpoint of the underlaying <see cref="SocksConnectionResult.Stream"/>
        /// </summary>
        public required SocksEndpoint LocalEndpoint { get; init; }

        public static SocksConnectionResult Failed(ConnectCode resultCode)
        {
            var result = new SocksConnectionResult()
            {
                Result = resultCode,
                Stream = null,
                LocalEndpoint = SocksEndpoint.Invalid,
            };
            if (result.Success)
                throw new ArgumentException("Not a failure code", nameof(resultCode));
            return result;
        }
        public static SocksConnectionResult Succeeded(Stream stream, SocksEndpoint localEndpoint)
        {
            ArgumentNullException.ThrowIfNull(stream);
            if (localEndpoint.AddressType == AddressType.Unknown)
                throw new ArgumentException($"Endpoint is of type {nameof(AddressType.Unknown)}", nameof(localEndpoint));

            return new SocksConnectionResult()
            {
                Result = ConnectCode.Succeeded,
                Stream = stream,
                LocalEndpoint = localEndpoint
            };
        }
    }
}
