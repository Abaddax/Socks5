using Abaddax.Socks5.Protocol.Enums;
using Pipelines.Extensions;
using Socks5.Clients;
using Socks5.Models;
using Socks5.Servers;
using System.Net;
using System.Net.Sockets;

namespace Abaddax.Socks5.Tests
{
    [NonParallelizable]
    public class InteropTest
    {
        const int _localPort = 11080;
        const int _remotePort = 12345;

        TcpListener _remoteListener;
        TcpClient? _remoteClient;

        [SetUp]
        public void Setup()
        {
            _remoteListener = new TcpListener(IPAddress.Loopback, _remotePort);
            _remoteListener.Start();
            _remoteClient = null;
        }

        [TearDown]
        public void Teardown()
        {
            _remoteListener.Dispose();
            _remoteClient?.Dispose();
        }

        [Test]
        public async Task ShouldConnectWithNoAuthenticationAndProxyData()
        {
            IPEndPoint serverEndpoint = new IPEndPoint(IPAddress.Loopback, _localPort);
            SimpleSocks5Server server = new SimpleSocks5Server(serverEndpoint, null);

            var clientOptions = new Socks5ClientOptions()
            {
                ValidateReceivedEndpoint = false
            }
                .WithConnectMethod(ConnectMethod.TCPConnect)
                .WithNoAuthenticationRequired();


            var serverTask = server.StartAsync();
            try
            {
                using var client = new TcpClient("127.0.0.1", _localPort);
                using var socksClient = new Socks5ClientProtocol(client.GetStream()) { Options = clientOptions };

                var connectTask = socksClient.ConnectAsync(AddressType.IPv4, "127.0.0.1", _remotePort);
                using var remotePeer = await _remoteListener.AcceptTcpClientAsync();
                await connectTask;

                Assert.That(socksClient.AddressType, Is.EqualTo(AddressType.IPv4));
                Assert.That(socksClient.Address, Is.EqualTo("127.0.0.1"));
                Assert.That(socksClient.Port, Is.EqualTo(_remotePort));

                Assert.That(socksClient.Stream, Is.Not.Null);

                await ShouldProxyData(socksClient.Stream, remotePeer.GetStream());
            }
            finally
            {
                server.Stop();
                await serverTask;
            }
        }

        [Test]
        public async Task ShouldConnectWithUsernamePasswordAndProxyData()
        {
            IPEndPoint serverEndpoint = new IPEndPoint(IPAddress.Loopback, _localPort);
            UsernamePassword userPass = new()
            {
                UserName = "user123",
                Password = "password123"
            };
            SimpleSocks5Server server = new SimpleSocks5Server(serverEndpoint, userPass);

            var clientOptions = new Socks5ClientOptions()
            {
                ValidateReceivedEndpoint = false
            }
                .WithConnectMethod(ConnectMethod.TCPConnect)
                .WithUsernamePasswordAuthentication("user123", "password123");

            var serverTask = server.StartAsync();
            try
            {
                using var client = new TcpClient("127.0.0.1", _localPort);
                using var socksClient = new Socks5ClientProtocol(client.GetStream()) { Options = clientOptions };

                var connectTask = socksClient.ConnectAsync(AddressType.IPv4, "127.0.0.1", _remotePort);
                using var remotePeer = await _remoteListener.AcceptTcpClientAsync();
                await connectTask;

                Assert.That(socksClient.AddressType, Is.EqualTo(AddressType.IPv4));
                Assert.That(socksClient.Address, Is.EqualTo("127.0.0.1"));
                Assert.That(socksClient.Port, Is.EqualTo(_remotePort));

                Assert.That(socksClient.Stream, Is.Not.Null);

                await ShouldProxyData(socksClient.Stream, remotePeer.GetStream());
            }
            finally
            {
                server.Stop();
                await serverTask;
            }
        }

        [Test]
        public async Task ShouldAcceptWithNoAuthenticationAndProxyData()
        {
            using var listener = new TcpListener(IPAddress.Loopback, _localPort);
            listener.Start();

            var serverOptions = new Socks5ServerOptions()
                .WithNoAuthenticationRequired()
                .WithConnectionHandler(async (method, type, address, port, cancellationToken) =>
                {
                    if (method != ConnectMethod.TCPConnect)
                        return (ConnectCode.NotAllowedByRuleset, null);

                    if (type != AddressType.IPv4 || address != "127.0.0.1" || port != _remotePort)
                        return (ConnectCode.ConnectionRefused, null);

                    var serverTask = _remoteListener.AcceptTcpClientAsync(cancellationToken);
                    var connection = new TcpClient();
                    await connection.ConnectAsync(address, port, cancellationToken);
                    _remoteClient = await serverTask;

                    return (ConnectCode.Succeeded, connection.GetStream());
                });

            Socks5CreateOption option = new()
            {
                Address = IPAddress.Loopback,
                Port = _localPort,
                UsernamePassword = null,
            };

            using var socksClient = new Socks5Client(option);
            var connectTask = socksClient.ConnectAsync(IPAddress.Loopback, _remotePort);

            using var server = await listener.AcceptTcpClientAsync();
            using var socksServer = new Socks5ServerProtocol(server.GetStream()) { Options = serverOptions };
            var acceptTask = socksServer.AcceptAsync();

            await acceptTask;
            await connectTask;

            Assert.That(socksServer.AddressType, Is.EqualTo(AddressType.IPv4));
            Assert.That(socksServer.Address, Is.EqualTo("127.0.0.1"));
            Assert.That(socksServer.Port, Is.EqualTo(_remotePort));

            Assert.That(socksServer.LocalStream, Is.Not.Null);
            Assert.That(socksServer.RemoteStream, Is.Not.Null);

            Assert.That(_remoteClient, Is.Not.Null);

            using var tokenSource = new CancellationTokenSource();
            var proxyTask = socksServer.ProxyAsync(tokenSource.Token);
            try
            {
                await ShouldProxyData(socksClient.GetPipe().AsStream(), _remoteClient!.GetStream());
            }
            finally
            {
                await tokenSource.CancelAsync();
                await proxyTask;
            }
        }

        [Test]
        public async Task ShouldAcceptWithUsernamePasswordAndProxyData()
        {
            using var listener = new TcpListener(IPAddress.Loopback, _localPort);
            listener.Start();

            var serverOptions = new Socks5ServerOptions()
                .WithUsernamePasswordAuthentication(async (username, password, _) =>
                {
                    if (username == "user123" && password == "password123")
                        return true;
                    return false;
                })
                .WithConnectionHandler(async (method, type, address, port, cancellationToken) =>
                {
                    if (method != ConnectMethod.TCPConnect)
                        return (ConnectCode.NotAllowedByRuleset, null);

                    if (type != AddressType.IPv4 || address != "127.0.0.1" || port != _remotePort)
                        return (ConnectCode.ConnectionRefused, null);

                    var serverTask = _remoteListener.AcceptTcpClientAsync(cancellationToken);
                    var connection = new TcpClient();
                    await connection.ConnectAsync(address, port, cancellationToken);
                    _remoteClient = await serverTask;

                    return (ConnectCode.Succeeded, connection.GetStream());
                });

            UsernamePassword userPass = new()
            {
                UserName = "user123",
                Password = "password123"
            };
            Socks5CreateOption option = new()
            {
                Address = IPAddress.Loopback,
                Port = _localPort,
                UsernamePassword = userPass,
            };

            using var socksClient = new Socks5Client(option);
            var connectTask = socksClient.ConnectAsync(IPAddress.Loopback, _remotePort);

            using var server = await listener.AcceptTcpClientAsync();
            using var socksServer = new Socks5ServerProtocol(server.GetStream()) { Options = serverOptions };
            var acceptTask = socksServer.AcceptAsync();

            await acceptTask;
            await connectTask;

            Assert.That(socksServer.AddressType, Is.EqualTo(AddressType.IPv4));
            Assert.That(socksServer.Address, Is.EqualTo("127.0.0.1"));
            Assert.That(socksServer.Port, Is.EqualTo(_remotePort));

            Assert.That(socksServer.LocalStream, Is.Not.Null);
            Assert.That(socksServer.RemoteStream, Is.Not.Null);

            Assert.That(_remoteClient, Is.Not.Null);

            using var tokenSource = new CancellationTokenSource();
            var proxyTask = socksServer.ProxyAsync(tokenSource.Token);
            try
            {
                await ShouldProxyData(socksClient.GetPipe().AsStream(), _remoteClient!.GetStream());
            }
            finally
            {
                await tokenSource.CancelAsync();
                await proxyTask;
            }
        }

        #region Helper
        private async Task ShouldProxyData(Stream clientStream, Stream remoteStream)
        {
            var receiveBuffer = new byte[100000];
            var sendBuffer = new byte[receiveBuffer.Length];

            Random.Shared.NextBytes(sendBuffer);

            //Socks-Client -> SocksServer -> Remote-Peer
            await clientStream.WriteAsync(sendBuffer);
            await remoteStream.ReadExactlyAsync(receiveBuffer);

            Assert.That(sendBuffer, Is.EquivalentTo(receiveBuffer));

            Random.Shared.NextBytes(sendBuffer);

            //Socks-Client <- SocksServer <- Remote-Peer
            await remoteStream.WriteAsync(sendBuffer);
            await clientStream.ReadExactlyAsync(receiveBuffer);

            Assert.That(sendBuffer, Is.EquivalentTo(receiveBuffer));
        }
        #endregion
    }
}
