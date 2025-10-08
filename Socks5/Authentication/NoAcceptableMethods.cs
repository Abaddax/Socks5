﻿using Abaddax.Socks5.Protocol.Enums;

namespace Abaddax.Socks5.Authentication
{
    internal sealed class NoAcceptableMethods : IAuthenticationHandler
    {
        public IEnumerable<AuthenticationMethod> SupportedMethods { get; } = [AuthenticationMethod.NoAcceptableMethods];

        public Task<AuthenticationMethod?> SelectAuthenticationMethod(IEnumerable<AuthenticationMethod> methods, CancellationToken cancellationToken)
        {
            return Task.FromResult<AuthenticationMethod?>(AuthenticationMethod.NoAcceptableMethods);
        }
        public Task<Stream> AuthenticationHandler(Stream stream, AuthenticationMethod method, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }
    }
}
