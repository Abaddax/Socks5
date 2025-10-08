using Abaddax.Socks5.Protocol.Enums;

namespace Abaddax.Socks5.Authentication
{
    public interface IAuthenticationHandler
    {
        /// <summary>
        /// AuthenticationMethods this handler supports
        /// </summary>
        IEnumerable<AuthenticationMethod> SupportedMethods { get; }

        /// <summary>
        /// Selected AuthenticationMethod from <paramref name="methods"/>
        /// </summary>
        /// <param name="methods">Methods the client supports</param>
        /// <returns><see langword="null"/> or <see cref="AuthenticationMethod.NoAcceptableMethods"/></returns>
        Task<AuthenticationMethod?> SelectAuthenticationMethod(IEnumerable<AuthenticationMethod> methods, CancellationToken cancellationToken);

        /// <summary>
        /// Authentication-Implementation on <paramref name="stream"/>
        /// </summary>
        /// <param name="stream">Raw stream to read and write if needed for authentication</param>
        /// <param name="method">Selected AuthenticationMethod</param>
        /// <returns>The stream to continue the handshake on</returns>
        Task<Stream> AuthenticationHandler(Stream stream, AuthenticationMethod method, CancellationToken cancellationToken);
    }
}
