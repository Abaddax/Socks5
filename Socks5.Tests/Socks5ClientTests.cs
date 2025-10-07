using Abaddax.Socks5.Protocol.Enums;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace Abaddax.Socks5.Tests
{
    [NonParallelizable]
    public class Socks5ClientTests
    {
        const int _localPort = 11080;
        const int _remotePort = 12345;

        TcpListener _listener;
        Socks5ServerOptions _serverOptions;
        X509Certificate2 _serverCertificate;

        string? clientUsername;
        string? clientPassword;
        AddressType? addressType;
        string? address;
        int? port;

        [SetUp]
        public void Setup()
        {
            _listener = new TcpListener(IPAddress.Loopback, _localPort);
            _listener.Start();

            _serverCertificate = Helper.GetSelfSignedCertificate();

            _serverOptions = new Socks5ServerOptions()
                .WithNoAuthenticationRequired()
                .WithUsernamePasswordAuthentication(async (username, password, token) =>
                {
                    clientUsername = username;
                    clientPassword = password;
                    return true;
                })
                .WithSecureSocketLayerAuthentication(async (stream, token) =>
                {
                    var tlsStream = new SslStream(stream, false, (sender, cert, chain, prolicy) => true);
                    await tlsStream.AuthenticateAsServerAsync(_serverCertificate);
                    return tlsStream;
                }, [0])
                .WithConnectionHandler(async (method, type, addr, p, token) =>
                {
                    if (method != ConnectMethod.TCPConnect)
                        return (ConnectCode.NotAllowedByRuleset, null);
                    addressType = type;
                    address = addr;
                    port = p;
                    return (ConnectCode.Succeeded, new MemoryStream());
                });
        }

        [TearDown]
        public void Teardown()
        {
            _listener.Dispose();
            _serverCertificate.Dispose();
        }

        [Test]
        public async Task ShouldConnectWithNoAuthenticationAndProxyData()
        {
            var clientOptions = new Socks5ClientOptions()
                .WithConnectMethod(ConnectMethod.TCPConnect)
                .WithNoAuthenticationRequired();

            var serverTask = _listener.AcceptTcpClientAsync();
            using var client = new TcpClient("127.0.0.1", _localPort);
            using var server = await serverTask;

            using var socksClient = new Socks5ClientProtocol(client.GetStream()) { Options = clientOptions };
            using var socksServer = new Socks5ServerProtocol(server.GetStream()) { Options = _serverOptions };

            var acceptTask = socksServer.AcceptAsync();
            var connectTask = socksClient.ConnectAsync(AddressType.IPv4, "127.0.0.1", _remotePort);

            await Task.WhenAll(connectTask, acceptTask);

            Assert.That(socksClient.AddressType, Is.EqualTo(AddressType.IPv4));
            Assert.That(socksClient.Address, Is.EqualTo("127.0.0.1"));
            Assert.That(socksClient.Port, Is.EqualTo(_remotePort));


            Assert.That(addressType, Is.EqualTo(AddressType.IPv4));
            Assert.That(address, Is.EqualTo("127.0.0.1"));
            Assert.That(port, Is.EqualTo(_remotePort));

            Assert.That(socksClient.Stream, Is.Not.Null);

            await ShouldProxyData(socksClient, socksServer);
        }

        [Test]
        public async Task ShouldConnectWithUsernamePasswordAndProxyData()
        {
            var clientOptions = new Socks5ClientOptions()
                .WithConnectMethod(ConnectMethod.TCPConnect)
                .WithUsernamePasswordAuthentication("user123", "password123");

            var serverTask = _listener.AcceptTcpClientAsync();
            using var client = new TcpClient("127.0.0.1", _localPort);
            using var server = await serverTask;

            using var socksClient = new Socks5ClientProtocol(client.GetStream()) { Options = clientOptions };
            using var socksServer = new Socks5ServerProtocol(server.GetStream()) { Options = _serverOptions };

            var acceptTask = socksServer.AcceptAsync();
            var connectTask = socksClient.ConnectAsync(AddressType.IPv6, "::1", _remotePort);

            await Task.WhenAll(connectTask, acceptTask);

            Assert.That(socksClient.AddressType, Is.EqualTo(AddressType.IPv6));
            Assert.That(socksClient.Address, Is.EqualTo("::1"));
            Assert.That(socksClient.Port, Is.EqualTo(_remotePort));

            Assert.That(addressType, Is.EqualTo(AddressType.IPv6));
            Assert.That(address, Is.EqualTo("::1"));
            Assert.That(port, Is.EqualTo(_remotePort));

            Assert.That(clientUsername, Is.EqualTo("user123"));
            Assert.That(clientPassword, Is.EqualTo("password123"));

            Assert.That(socksClient.Stream, Is.Not.Null);

            await ShouldProxyData(socksClient, socksServer);
        }

        [Test]
        public async Task ShouldConnectWithSecureSocketLayerAndProxyData()
        {
            var clientOptions = new Socks5ClientOptions()
               .WithConnectMethod(ConnectMethod.TCPConnect)
               .WithSecureSocketLayerAuthentication(async (stream, token) =>
               {
                   var tlsStream = new SslStream(stream, false, (sender, cert, chain, prolicy) => true);
                   await tlsStream.AuthenticateAsClientAsync("localhost");
                   return tlsStream;
               }, [0]);

            var serverTask = _listener.AcceptTcpClientAsync();
            using var client = new TcpClient("127.0.0.1", _localPort);
            using var server = await serverTask;

            using var socksClient = new Socks5ClientProtocol(client.GetStream()) { Options = clientOptions };
            using var socksServer = new Socks5ServerProtocol(server.GetStream()) { Options = _serverOptions };

            var acceptTask = socksServer.AcceptAsync();
            var connectTask = socksClient.ConnectAsync(AddressType.DomainName, "localhost", _remotePort);

            await Task.WhenAll(connectTask, acceptTask);

            Assert.That(socksClient.AddressType, Is.EqualTo(AddressType.DomainName));
            Assert.That(socksClient.Address, Is.EqualTo("localhost"));
            Assert.That(socksClient.Port, Is.EqualTo(_remotePort));

            Assert.That(addressType, Is.EqualTo(AddressType.DomainName));
            Assert.That(address, Is.EqualTo("localhost"));
            Assert.That(port, Is.EqualTo(_remotePort));

            Assert.That(socksClient.Stream, Is.Not.Null);

            await ShouldProxyData(socksClient, socksServer);
        }

        [Test]
        public async Task ShouldAbortWhenNoAcceptableMethods()
        {
            var clientOptions = new Socks5ClientOptions()
               .WithConnectMethod(ConnectMethod.TCPConnect)
               .WithSecureSocketLayerAuthentication(async (stream, token) =>
               {
                   var tlsStream = new SslStream(stream, false, (sender, cert, chain, prolicy) => true);
                   await tlsStream.AuthenticateAsClientAsync("localhost");
                   return tlsStream;
               }, [0]);
            var serverOptions = new Socks5ServerOptions()
                .WithNoAcceptableAuthentication();

            var serverTask = _listener.AcceptTcpClientAsync();
            using var client = new TcpClient("127.0.0.1", _localPort);
            using var server = await serverTask;

            using var socksClient = new Socks5ClientProtocol(client.GetStream()) { Options = clientOptions };
            using var socksServer = new Socks5ServerProtocol(server.GetStream()) { Options = serverOptions };

            var acceptTask = socksServer.AcceptAsync();
            var connectTask = socksClient.ConnectAsync(AddressType.DomainName, "github.com", _remotePort);

            Assert.ThrowsAsync(Is.Not.Null, async () => await acceptTask);
            Assert.ThrowsAsync(Is.Not.Null, async () => await connectTask);

            Assert.That(socksClient.AddressType, Is.EqualTo(AddressType.IPv4));
            Assert.That(socksClient.Address, Is.EqualTo("0.0.0.0"));
            Assert.That(socksClient.Port, Is.EqualTo(0));

            Assert.That(addressType, Is.Null);
            Assert.That(address, Is.Null);
            Assert.That(port, Is.Null);

            Assert.Throws<InvalidOperationException>(() => { _ = socksClient.Stream; });
        }

        [Test]
        public async Task ShouldSupportMultipleMethods()
        {
            var clientOptions = new Socks5ClientOptions()
                .WithConnectMethod(ConnectMethod.TCPConnect)
                .WithNoAuthenticationRequired()
                .WithUsernamePasswordAuthentication("user1234", "password1234");
            var serverOptions1 = new Socks5ServerOptions()
                .WithUsernamePasswordAuthentication(async (username, password, token) =>
                {
                    if (username == "user1234" &&
                        password == "password1234")
                        return true;
                    return false;
                })
                .WithConnectionHandler(async (method, type, addr, p, token) =>
                {
                    return (ConnectCode.Succeeded, new MemoryStream());
                });
            var serverOptions2 = new Socks5ServerOptions()
                .WithNoAuthenticationRequired()
                .WithConnectionHandler(async (method, type, addr, p, token) =>
                {
                    return (ConnectCode.Succeeded, new MemoryStream());
                });

            //Option 1
            {
                var serverTask = _listener.AcceptTcpClientAsync();
                using var client = new TcpClient("127.0.0.1", _localPort);
                using var server = await serverTask;

                using var socksClient = new Socks5ClientProtocol(client.GetStream()) { Options = clientOptions };
                using var socksServer = new Socks5ServerProtocol(server.GetStream()) { Options = serverOptions1 };

                var acceptTask = socksServer.AcceptAsync();
                var connectTask = socksClient.ConnectAsync(AddressType.IPv4, "127.0.0.1", _remotePort);

                await Task.WhenAll(connectTask, acceptTask);

                Assert.That(socksClient.AddressType, Is.EqualTo(AddressType.IPv4));
                Assert.That(socksClient.Address, Is.EqualTo("127.0.0.1"));
                Assert.That(socksClient.Port, Is.EqualTo(_remotePort));

                await ShouldProxyData(socksClient, socksServer);
            }

            //Option 2
            {
                var serverTask = _listener.AcceptTcpClientAsync();
                using var client = new TcpClient("127.0.0.1", _localPort);
                using var server = await serverTask;

                using var socksClient = new Socks5ClientProtocol(client.GetStream()) { Options = clientOptions };
                using var socksServer = new Socks5ServerProtocol(server.GetStream()) { Options = serverOptions2 };

                var acceptTask = socksServer.AcceptAsync();
                var connectTask = socksClient.ConnectAsync(AddressType.IPv4, "127.0.0.1", _remotePort);

                await Task.WhenAll(connectTask, acceptTask);

                Assert.That(socksClient.AddressType, Is.EqualTo(AddressType.IPv4));
                Assert.That(socksClient.Address, Is.EqualTo("127.0.0.1"));
                Assert.That(socksClient.Port, Is.EqualTo(_remotePort));

                await ShouldProxyData(socksClient, socksServer);
            }

        }

        #region Helper
        private async Task ShouldProxyData(Socks5ClientProtocol client, Socks5ServerProtocol server)
        {
            var receiveBuffer = new byte[100000];
            var sendBuffer = new byte[receiveBuffer.Length];

            //Async functions
            {
                Random.Shared.NextBytes(sendBuffer);

                await server.LocalStream.WriteAsync(sendBuffer);
                await client.Stream.ReadExactlyAsync(receiveBuffer);

                Assert.That(sendBuffer, Is.EquivalentTo(receiveBuffer));

                Random.Shared.NextBytes(sendBuffer);

                await client.Stream.WriteAsync(sendBuffer);
                await server.LocalStream.ReadExactlyAsync(receiveBuffer);

                Assert.That(sendBuffer, Is.EquivalentTo(receiveBuffer));
            }

            //Sync functions
            {
                Random.Shared.NextBytes(sendBuffer);

                server.LocalStream.Write(sendBuffer);
                client.Stream.ReadExactly(receiveBuffer);

                Assert.That(sendBuffer, Is.EquivalentTo(receiveBuffer));

                Random.Shared.NextBytes(sendBuffer);

                client.Stream.Write(sendBuffer);
                server.LocalStream.ReadExactly(receiveBuffer);

                Assert.That(sendBuffer, Is.EquivalentTo(receiveBuffer));
            }
        }
        #endregion
    }
}
