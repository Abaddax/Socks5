using Abaddax.Utilities.Buffers;
using Abaddax.Utilities.Network;
using Socks5.Protocol;
using System.Text;

namespace Socks5.Authentication
{
    public delegate Task<bool> UserLoginHandler(string username, string password, CancellationToken token);
    internal sealed class UsernamePasswordClient : IAuthenticationHandler
    {
        private readonly string _username;
        private readonly string _password;

        public UsernamePasswordClient(string username, string password)
        {
            _username = username ?? throw new ArgumentNullException(nameof(username));
            _password = password ?? throw new ArgumentNullException(nameof(password));
            if (Encoding.UTF8.GetByteCount(_username) > 0xff)
                throw new ArgumentOutOfRangeException(nameof(username), "Username can not be longer then 255");
            if (Encoding.UTF8.GetByteCount(_password) > 0xff)
                throw new ArgumentOutOfRangeException(nameof(password), "Password can not be longer then 255");
        }

        public IEnumerable<AuthenticationMethod> SupportedMethods { get; } = [AuthenticationMethod.UsernamePassword];
        public async Task<AuthenticationMethod?> SelectAuthenticationMethod(IEnumerable<AuthenticationMethod> methods, CancellationToken token)
        {
            if (methods?.Any(x => x == AuthenticationMethod.UsernamePassword) ?? false)
                return AuthenticationMethod.UsernamePassword;
            return null;
        }
        public async Task<Stream> AuthenticationHandler(Stream stream, AuthenticationMethod method, CancellationToken token)
        {
            if (method != AuthenticationMethod.UsernamePassword)
                throw new NotSupportedException();

            var request = new UserAuthenticationRequest()
            {
                SubnegotiationVersion = 1,
                Username = _username,
                Password = _password
            };
            await request.WriteAsync(stream, request, token);

            var response = new UserAuthenticationResponse();
            response = await response.ReadAsync(stream, token);

            if (request.SubnegotiationVersion != response.SubnegotiationVersion ||
                response.Status != 0)
                throw new Exception("Failed to authenticate");

            return stream;
        }
    }

    internal sealed class UsernamePasswordServer : IAuthenticationHandler
    {
        private readonly UserLoginHandler _loginhandler;

        public UsernamePasswordServer(UserLoginHandler loginhandler)
        {
            _loginhandler = loginhandler ?? throw new ArgumentNullException(nameof(loginhandler));
        }

        public IEnumerable<AuthenticationMethod> SupportedMethods { get; } = new AuthenticationMethod[] { AuthenticationMethod.UsernamePassword };
        public async Task<AuthenticationMethod?> SelectAuthenticationMethod(IEnumerable<AuthenticationMethod> methods, CancellationToken token)
        {
            if (methods?.Any(x => x == AuthenticationMethod.UsernamePassword) ?? false)
                return AuthenticationMethod.UsernamePassword;
            return null;
        }
        public async Task<Stream> AuthenticationHandler(Stream stream, AuthenticationMethod method, CancellationToken token)
        {
            if (method != AuthenticationMethod.UsernamePassword)
                throw new NotSupportedException();

            var request = new UserAuthenticationRequest();
            request = await request.ReadAsync(stream, token);

            bool allow;
            try
            {
                allow = await _loginhandler.Invoke(request.Username, request.Password, token);
            }
            catch (Exception ex)
            {
                allow = false;
            }

            var response = new UserAuthenticationResponse()
            {
                SubnegotiationVersion = request.SubnegotiationVersion,
                Status = (byte)(allow ? 0 : 1)
            };
            await response.WriteAsync(stream, response, token);

            return stream;
        }

    }

    #region Helper
    internal struct UserAuthenticationRequest : IStreamParser<UserAuthenticationRequest>
    {
        public byte SubnegotiationVersion;
        public string Username;
        public string Password;

        public async Task<UserAuthenticationRequest> ReadAsync(Stream stream, CancellationToken token)
        {
            var message = new UserAuthenticationRequest();

            using var header = BufferPool<byte>.Rent(2);
            await stream.ReadExactlyAsync(header, token);

            message.SubnegotiationVersion = header[0];
            if (message.SubnegotiationVersion != 1)
                throw new Exception("Invalid subnegotiation-version");

            var usernameLength = header[1];
            using var usernameBuffer = BufferPool<byte>.Rent(usernameLength);
            await stream.ReadExactlyAsync(usernameBuffer, token);

            message.Username = Encoding.UTF8.GetString(usernameBuffer);

            var passwordLength = stream.ReadByte();
            if (passwordLength < byte.MinValue || passwordLength > byte.MaxValue)
                throw new EndOfStreamException();

            using var passwordBuffer = BufferPool<byte>.Rent(passwordLength);
            await stream.ReadExactlyAsync(passwordBuffer, token);

            message.Password = Encoding.UTF8.GetString(passwordBuffer);

            return message;
        }
        public async Task WriteAsync(Stream stream, UserAuthenticationRequest message, CancellationToken token)
        {
            var userNameLength = Encoding.UTF8.GetByteCount(message.Username);
            var passwordLength = Encoding.UTF8.GetByteCount(message.Password);

            using var buffer = BufferPool<byte>.Rent(3 + userNameLength + passwordLength);

            buffer[0] = message.SubnegotiationVersion;
            buffer[1] = (byte)userNameLength;

            Encoding.UTF8.GetBytes(message.Username, buffer.Span.Slice(2, userNameLength));
            buffer[2 + userNameLength] = (byte)passwordLength;
            Encoding.UTF8.GetBytes(message.Password, buffer.Span.Slice(3 + userNameLength, passwordLength));

            await stream.WriteAsync(buffer, token);
        }
    }
    internal struct UserAuthenticationResponse : IStreamParser<UserAuthenticationResponse>
    {
        public byte SubnegotiationVersion;
        public byte Status;

        public async Task<UserAuthenticationResponse> ReadAsync(Stream stream, CancellationToken token)
        {
            var message = new UserAuthenticationResponse();

            using var header = BufferPool<byte>.Rent(2);
            await stream.ReadExactlyAsync(header, token);

            message.SubnegotiationVersion = header[0];
            if (message.SubnegotiationVersion != 1)
                throw new Exception("Invalid subnegotiation-version");

            message.Status = header[1];

            return message;
        }
        public async Task WriteAsync(Stream stream, UserAuthenticationResponse message, CancellationToken token)
        {
            using var buffer = BufferPool<byte>.Rent(2);
            buffer[0] = message.SubnegotiationVersion;
            buffer[1] = message.Status;

            await stream.WriteAsync(buffer, token);
        }
    }
    #endregion
}
