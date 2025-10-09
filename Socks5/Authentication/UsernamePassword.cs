using Abaddax.Socks5.Protocol.Enums;
using Abaddax.Utilities.Network;
using System.Text;

namespace Abaddax.Socks5.Authentication
{
    public delegate Task<bool> UserLoginHandler(string username, string password, CancellationToken cancellationToken);
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
        public Task<AuthenticationMethod?> SelectAuthenticationMethod(IEnumerable<AuthenticationMethod> methods, CancellationToken cancellationToken)
        {
            if (methods?.Any(x => x == AuthenticationMethod.UsernamePassword) ?? false)
                return Task.FromResult<AuthenticationMethod?>(AuthenticationMethod.UsernamePassword);
            return Task.FromResult<AuthenticationMethod?>(null);
        }
        public async Task<Stream> AuthenticationHandler(Stream stream, AuthenticationMethod method, CancellationToken cancellationToken)
        {
            if (method != AuthenticationMethod.UsernamePassword)
                throw new NotSupportedException();

            var request = new UserAuthenticationRequest()
            {
                SubnegotiationVersion = 1,
                Username = _username,
                Password = _password
            };
            await request.WriteAsync(stream, request, cancellationToken);

            var response = new UserAuthenticationResponse();
            response = await response.ReadAsync(stream, cancellationToken);

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
        public Task<AuthenticationMethod?> SelectAuthenticationMethod(IEnumerable<AuthenticationMethod> methods, CancellationToken cancellationToken)
        {
            if (methods?.Any(x => x == AuthenticationMethod.UsernamePassword) ?? false)
                return Task.FromResult<AuthenticationMethod?>(AuthenticationMethod.UsernamePassword);
            return Task.FromResult<AuthenticationMethod?>(null);
        }
        public async Task<Stream> AuthenticationHandler(Stream stream, AuthenticationMethod method, CancellationToken cancellationToken)
        {
            if (method != AuthenticationMethod.UsernamePassword)
                throw new NotSupportedException();

            var request = new UserAuthenticationRequest();
            request = await request.ReadAsync(stream, cancellationToken);

            bool allow;
            try
            {
                allow = await _loginhandler.Invoke(request.Username, request.Password, cancellationToken);
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
            await response.WriteAsync(stream, response, cancellationToken);

            return stream;
        }

    }

    #region Helper
    internal record struct UserAuthenticationRequest : IStreamParser<UserAuthenticationRequest>
    {
        public byte SubnegotiationVersion { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }

        public readonly async Task<UserAuthenticationRequest> ReadAsync(Stream stream, CancellationToken cancellationToken)
        {
            var message = new UserAuthenticationRequest();

            var header = new byte[2];
            await stream.ReadExactlyAsync(header, cancellationToken);

            message.SubnegotiationVersion = header[0];
            if (message.SubnegotiationVersion != 1)
                throw new Exception("Invalid subnegotiation-version");

            var usernameLength = header[1];
            var usernameBuffer = new byte[usernameLength];
            await stream.ReadExactlyAsync(usernameBuffer, cancellationToken);

            message.Username = Encoding.UTF8.GetString(usernameBuffer);

            var passwordLength = stream.ReadByte();
            if (passwordLength < byte.MinValue || passwordLength > byte.MaxValue)
                throw new EndOfStreamException();

            var passwordBuffer = new byte[passwordLength];
            await stream.ReadExactlyAsync(passwordBuffer, cancellationToken);

            message.Password = Encoding.UTF8.GetString(passwordBuffer);

            return message;
        }
        public readonly async Task WriteAsync(Stream stream, UserAuthenticationRequest message, CancellationToken cancellationToken)
        {
            var userNameLength = Encoding.UTF8.GetByteCount(message.Username);
            var passwordLength = Encoding.UTF8.GetByteCount(message.Password);

            var buffer = new byte[3 + userNameLength + passwordLength];

            buffer[0] = message.SubnegotiationVersion;
            buffer[1] = (byte)userNameLength;

            Encoding.UTF8.GetBytes(message.Username, buffer.AsSpan(2, userNameLength));
            buffer[2 + userNameLength] = (byte)passwordLength;
            Encoding.UTF8.GetBytes(message.Password, buffer.AsSpan(3 + userNameLength, passwordLength));

            await stream.WriteAsync(buffer, cancellationToken);
        }
    }
    internal record struct UserAuthenticationResponse : IStreamParser<UserAuthenticationResponse>
    {
        public byte SubnegotiationVersion { get; set; }
        public byte Status { get; set; }

        public readonly async Task<UserAuthenticationResponse> ReadAsync(Stream stream, CancellationToken cancellationToken)
        {
            var message = new UserAuthenticationResponse();

            var header = new byte[2];
            await stream.ReadExactlyAsync(header, cancellationToken);

            message.SubnegotiationVersion = header[0];
            if (message.SubnegotiationVersion != 1)
                throw new Exception("Invalid subnegotiation-version");

            message.Status = header[1];

            return message;
        }
        public readonly async Task WriteAsync(Stream stream, UserAuthenticationResponse message, CancellationToken cancellationToken)
        {
            var buffer = new byte[2];
            buffer[0] = message.SubnegotiationVersion;
            buffer[1] = message.Status;

            await stream.WriteAsync(buffer, cancellationToken);
        }
    }
    #endregion
}
