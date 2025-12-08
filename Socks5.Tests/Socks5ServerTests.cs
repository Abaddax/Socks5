using Abaddax.Socks5.Protocol;
using Abaddax.Socks5.Protocol.Enums;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace Abaddax.Socks5.Tests
{
    [NonParallelizable]
    public class Socks5ServerTests
    {
        const ushort _localPort = 61080;
        const ushort _remotePort = 54321;

        TcpListener _listener;
        TcpListener _remoteListener;
        TcpClient? _remoteClient;
        Socks5ClientOptions _clientOptions;
        X509Certificate2 _serverCertificate;

        [SetUp]
        public void Setup()
        {
            _listener = new TcpListener(IPAddress.Loopback, _localPort);
            _listener.Start();
            _remoteListener = new TcpListener(IPAddress.Loopback, _remotePort);
            _remoteListener.Start();
            _remoteClient = null;

            _serverCertificate = Helper.GetSelfSignedCertificate();

            _clientOptions = new Socks5ClientOptions()
                .WithNoAuthenticationRequired()
                .WithConnectMethod(ConnectMethod.TCPConnect)
                .WithUsernamePasswordAuthentication("user123", "password123")
                .WithSecureSocketLayerAuthentication(async (stream, cancellationToken) =>
                {
                    var tlsStream = new SslStream(stream, false, (sender, cert, chain, prolicy) => true);
                    await tlsStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions()
                    {
                        TargetHost = "localhost"
                    }, cancellationToken);
                    return tlsStream;
                }, [0]);
        }

        [TearDown]
        public void Teardown()
        {
            _listener.Dispose();
            _remoteListener.Dispose();
            _serverCertificate.Dispose();
            _remoteClient?.Dispose();
        }

        [Test]
        public async Task ShouldAcceptWithNoAuthenticationAndProxyData()
        {
            var serverOptions = new Socks5ServerOptions()
                .WithNoAuthenticationRequired()
                .WithConnectionHandler(async (method, endpoint, cancellationToken) =>
                {
                    if (method != ConnectMethod.TCPConnect)
                        return SocksConnectionResult.Failed(ConnectCode.NotAllowedByRuleset);

                    if (endpoint.AddressType != AddressType.IPv4 || endpoint.Address != "127.0.0.1" || endpoint.Port != _remotePort)
                        return SocksConnectionResult.Failed(ConnectCode.ConnectionRefused);

                    var serverTask = _remoteListener.AcceptTcpClientAsync(cancellationToken);
                    var connection = new TcpClient();
                    await connection.ConnectAsync(endpoint.Address, endpoint.Port, cancellationToken);
                    _remoteClient = await serverTask;

                    return SocksConnectionResult.Succeeded(connection.GetStream(), (SocksEndpoint)connection.Client.LocalEndPoint);
                });

            var serverTask = _listener.AcceptTcpClientAsync();
            using var client = new TcpClient("127.0.0.1", _localPort);
            using var server = await serverTask;

            using var socksClient = new Socks5ClientProtocol(client.GetStream()) { Options = _clientOptions };
            using var socksServer = new Socks5ServerProtocol(server.GetStream()) { Options = serverOptions };

            var acceptTask = socksServer.AcceptAsync();
            var connectTask = socksClient.ConnectAsync(AddressType.IPv4, "127.0.0.1", _remotePort);

            await Task.WhenAll(connectTask, acceptTask);

            Assert.That(socksServer.RemoteEndpoint.AddressType, Is.EqualTo(AddressType.IPv4));
            Assert.That(socksServer.RemoteEndpoint.Address, Is.EqualTo("127.0.0.1"));
            Assert.That(socksServer.RemoteEndpoint.Port, Is.EqualTo(_remotePort));

            Assert.That(socksServer.LocalEndpoint, Is.Not.EqualTo(SocksEndpoint.Invalid));

            Assert.That(socksServer.LocalEndpoint, Is.EqualTo(socksClient.LocalEndpoint));
            Assert.That(socksServer.RemoteEndpoint, Is.EqualTo(socksClient.RemoteEndpoint));

            Assert.That(socksServer.LocalStream, Is.Not.Null);
            Assert.That(socksServer.RemoteStream, Is.Not.Null);

            await ShouldProxyData(socksClient, socksServer);
        }

        [Test]
        public async Task ShouldAcceptWithUsernamePasswordAndProxyData()
        {
            var serverOptions = new Socks5ServerOptions()
                .WithUsernamePasswordAuthentication(async (username, password, _) =>
                {
                    if (username == "user123" && password == "password123")
                        return true;
                    return false;
                })
                .WithConnectionHandler(async (method, endpoint, cancellationToken) =>
                {
                    if (method != ConnectMethod.TCPConnect)
                        return SocksConnectionResult.Failed(ConnectCode.NotAllowedByRuleset);

                    if (endpoint.AddressType != AddressType.IPv4 || endpoint.Address != "127.0.0.1" || endpoint.Port != _remotePort)
                        return SocksConnectionResult.Failed(ConnectCode.ConnectionRefused);

                    var serverTask = _remoteListener.AcceptTcpClientAsync(cancellationToken);
                    var connection = new TcpClient();
                    await connection.ConnectAsync(endpoint.Address, endpoint.Port, cancellationToken);
                    _remoteClient = await serverTask;

                    return SocksConnectionResult.Succeeded(connection.GetStream(), (SocksEndpoint)connection.Client.LocalEndPoint);
                });

            var serverTask = _listener.AcceptTcpClientAsync();
            using var client = new TcpClient("127.0.0.1", _localPort);
            using var server = await serverTask;

            using var socksClient = new Socks5ClientProtocol(client.GetStream()) { Options = _clientOptions };
            using var socksServer = new Socks5ServerProtocol(server.GetStream()) { Options = serverOptions };

            var acceptTask = socksServer.AcceptAsync();
            var connectTask = socksClient.ConnectAsync(AddressType.IPv4, "127.0.0.1", _remotePort);

            await Task.WhenAll(connectTask, acceptTask);

            Assert.That(socksServer.RemoteEndpoint.AddressType, Is.EqualTo(AddressType.IPv4));
            Assert.That(socksServer.RemoteEndpoint.Address, Is.EqualTo("127.0.0.1"));
            Assert.That(socksServer.RemoteEndpoint.Port, Is.EqualTo(_remotePort));

            Assert.That(socksServer.LocalEndpoint, Is.Not.EqualTo(SocksEndpoint.Invalid));

            Assert.That(socksServer.LocalEndpoint, Is.EqualTo(socksClient.LocalEndpoint));
            Assert.That(socksServer.RemoteEndpoint, Is.EqualTo(socksClient.RemoteEndpoint));

            Assert.That(socksServer.LocalStream, Is.Not.Null);
            Assert.That(socksServer.RemoteStream, Is.Not.Null);

            await ShouldProxyData(socksClient, socksServer);
        }

        [Test]
        public async Task ShouldAccepttWithSecureSocketLayerAndProxyData()
        {
            var serverOptions = new Socks5ServerOptions()
                 .WithSecureSocketLayerAuthentication(async (stream, cancellationToken) =>
                 {
                     var tlsStream = new SslStream(stream, false, (sender, cert, chain, prolicy) => true);
                     await tlsStream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions()
                     {
                         ServerCertificate = _serverCertificate
                     }, cancellationToken);
                     return tlsStream;
                 }, [0])
                 .WithConnectionHandler(async (method, endpoint, cancellationToken) =>
                 {
                     if (method != ConnectMethod.TCPConnect)
                         return SocksConnectionResult.Failed(ConnectCode.NotAllowedByRuleset);

                     if (endpoint.AddressType != AddressType.IPv4 || endpoint.Address != "127.0.0.1" || endpoint.Port != _remotePort)
                         return SocksConnectionResult.Failed(ConnectCode.ConnectionRefused);

                     var serverTask = _remoteListener.AcceptTcpClientAsync(cancellationToken);
                     var connection = new TcpClient();
                     await connection.ConnectAsync(endpoint.Address, endpoint.Port, cancellationToken);
                     _remoteClient = await serverTask;

                     return SocksConnectionResult.Succeeded(connection.GetStream(), (SocksEndpoint)connection.Client.LocalEndPoint);
                 });

            var serverTask = _listener.AcceptTcpClientAsync();
            using var client = new TcpClient("127.0.0.1", _localPort);
            using var server = await serverTask;

            using var socksClient = new Socks5ClientProtocol(client.GetStream()) { Options = _clientOptions };
            using var socksServer = new Socks5ServerProtocol(server.GetStream()) { Options = serverOptions };

            var acceptTask = socksServer.AcceptAsync();
            var connectTask = socksClient.ConnectAsync(AddressType.IPv4, "127.0.0.1", _remotePort);

            await Task.WhenAll(connectTask, acceptTask);

            Assert.That(socksServer.RemoteEndpoint.AddressType, Is.EqualTo(AddressType.IPv4));
            Assert.That(socksServer.RemoteEndpoint.Address, Is.EqualTo("127.0.0.1"));
            Assert.That(socksServer.RemoteEndpoint.Port, Is.EqualTo(_remotePort));

            Assert.That(socksServer.LocalEndpoint, Is.Not.EqualTo(SocksEndpoint.Invalid));

            Assert.That(socksServer.LocalEndpoint, Is.EqualTo(socksClient.LocalEndpoint));
            Assert.That(socksServer.RemoteEndpoint, Is.EqualTo(socksClient.RemoteEndpoint));

            Assert.That(socksServer.LocalStream, Is.Not.Null);
            Assert.That(socksServer.RemoteStream, Is.Not.Null);

            await ShouldProxyData(socksClient, socksServer);
        }

        [Test]
        public async Task ShouldNotAcceptWhenNoAcceptableMethods()
        {
            var clientOptions = new Socks5ClientOptions()
                .WithConnectMethod(ConnectMethod.TCPConnect)
                .WithUsernamePasswordAuthentication("user123", "password123");
            var serverOptions = new Socks5ServerOptions()
                .WithNoAuthenticationRequired();

            var serverTask = _listener.AcceptTcpClientAsync();
            using var client = new TcpClient("127.0.0.1", _localPort);
            using var server = await serverTask;

            using var socksClient = new Socks5ClientProtocol(client.GetStream()) { Options = clientOptions };
            using var socksServer = new Socks5ServerProtocol(server.GetStream()) { Options = serverOptions };

            var acceptTask = socksServer.AcceptAsync();
            var connectTask = socksClient.ConnectAsync(AddressType.IPv4, "127.0.0.1", _remotePort);

            Assert.ThrowsAsync(Is.Not.Null, async () => await acceptTask);
            Assert.ThrowsAsync(Is.Not.Null, async () => await connectTask);

            Assert.That(socksServer.RemoteEndpoint, Is.EqualTo(SocksEndpoint.Invalid));
            Assert.That(socksServer.LocalEndpoint, Is.EqualTo(SocksEndpoint.Invalid));

            Assert.Throws<InvalidOperationException>(() => { _ = socksServer.LocalStream; });
            Assert.Throws<InvalidOperationException>(() => { _ = socksServer.RemoteStream; });
        }

        [Test]
        public async Task ShouldNotAcceptWhenInvalidUsernamePassword()
        {
            var serverOptions = new Socks5ServerOptions()
               .WithUsernamePasswordAuthentication(async (username, password, _) =>
               {
                   if (username == "user1234" &&
                       password == "password1234")
                       return true;
                   return false;
               })
               .WithConnectionHandler(async (method, endpoint, cancellationToken) =>
               {
                   if (method != ConnectMethod.TCPConnect)
                       return SocksConnectionResult.Failed(ConnectCode.NotAllowedByRuleset);

                   if (endpoint.AddressType != AddressType.IPv4 || endpoint.Address != "127.0.0.1" || endpoint.Port != _remotePort)
                       return SocksConnectionResult.Failed(ConnectCode.ConnectionRefused);

                   var serverTask = _remoteListener.AcceptTcpClientAsync(cancellationToken);
                   var connection = new TcpClient();
                   await connection.ConnectAsync(endpoint.Address, endpoint.Port, cancellationToken);
                   _remoteClient = await serverTask;

                   return SocksConnectionResult.Succeeded(connection.GetStream(), (SocksEndpoint)connection.Client.LocalEndPoint);
               });

            var serverTask = _listener.AcceptTcpClientAsync();
            using var client = new TcpClient("127.0.0.1", _localPort);
            using var server = await serverTask;

            using var socksClient = new Socks5ClientProtocol(client.GetStream()) { Options = _clientOptions };
            using var socksServer = new Socks5ServerProtocol(server.GetStream()) { Options = serverOptions };

            var acceptTask = socksServer.AcceptAsync();
            var connectTask = socksClient.ConnectAsync(AddressType.IPv4, "127.0.0.1", _remotePort);

            Assert.ThrowsAsync(Is.Not.Null, async () => await acceptTask);
            Assert.ThrowsAsync(Is.Not.Null, async () => await connectTask);

            Assert.That(socksServer.RemoteEndpoint, Is.EqualTo(SocksEndpoint.Invalid));
            Assert.That(socksServer.LocalEndpoint, Is.EqualTo(SocksEndpoint.Invalid));

            Assert.Throws<InvalidOperationException>(() => { _ = socksServer.LocalStream; });
            Assert.Throws<InvalidOperationException>(() => { _ = socksServer.RemoteStream; });
        }

        [Test]
        public async Task ShouldNotAcceptWhenInvalidCertificate()
        {
            var serverOptions = new Socks5ServerOptions()
               .WithSecureSocketLayerAuthentication(async (stream, cancellationToken) =>
               {
                   var tlsStream = new SslStream(stream, false, (sender, cert, chain, prolicy) => false);
                   await tlsStream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions()
                   {
                       ServerCertificate = _serverCertificate
                   }, cancellationToken);
                   return tlsStream;
               }, [0])
               .WithConnectionHandler(async (method, endpoint, cancellationToken) =>
               {
                   if (method != ConnectMethod.TCPConnect)
                       return SocksConnectionResult.Failed(ConnectCode.NotAllowedByRuleset);

                   if (endpoint.AddressType != AddressType.IPv4 || endpoint.Address != "127.0.0.1" || endpoint.Port != _remotePort)
                       return SocksConnectionResult.Failed(ConnectCode.ConnectionRefused);

                   var serverTask = _remoteListener.AcceptTcpClientAsync(cancellationToken);
                   var connection = new TcpClient();
                   await connection.ConnectAsync(endpoint.Address, endpoint.Port, cancellationToken);
                   _remoteClient = await serverTask;

                   return SocksConnectionResult.Succeeded(connection.GetStream(), (SocksEndpoint)connection.Client.LocalEndPoint);
               });

            var serverTask = _listener.AcceptTcpClientAsync();
            using var client = new TcpClient("127.0.0.1", _localPort);
            using var server = await serverTask;

            using var socksClient = new Socks5ClientProtocol(client.GetStream()) { Options = _clientOptions };
            using var socksServer = new Socks5ServerProtocol(server.GetStream()) { Options = serverOptions };

            var acceptTask = socksServer.AcceptAsync();
            var connectTask = socksClient.ConnectAsync(AddressType.IPv4, "127.0.0.1", _remotePort);

            Assert.ThrowsAsync(Is.Not.Null, async () => await acceptTask);
            Assert.ThrowsAsync(Is.Not.Null, async () => await connectTask);

            Assert.That(socksServer.RemoteEndpoint, Is.EqualTo(SocksEndpoint.Invalid));
            Assert.That(socksServer.LocalEndpoint, Is.EqualTo(SocksEndpoint.Invalid));

            Assert.Throws<InvalidOperationException>(() => { _ = socksServer.LocalStream; });
            Assert.Throws<InvalidOperationException>(() => { _ = socksServer.RemoteStream; });
        }


        [Test]
        public async Task ShouldSupportMultipleMethods()
        {
            var serverOptions = new Socks5ServerOptions()
                .WithNoAuthenticationRequired()
                .WithUsernamePasswordAuthentication(async (username, password, _) =>
                {
                    if (username == "user123" &&
                        password == "password123")
                        return true;
                    return false;
                })
                .WithConnectionHandler(async (method, endpoint, cancellationToken) =>
                {
                    if (method != ConnectMethod.TCPConnect)
                        return SocksConnectionResult.Failed(ConnectCode.NotAllowedByRuleset);

                    if (endpoint.AddressType != AddressType.IPv4 || endpoint.Address != "127.0.0.1" || endpoint.Port != _remotePort)
                        return SocksConnectionResult.Failed(ConnectCode.ConnectionRefused);

                    var serverTask = _remoteListener.AcceptTcpClientAsync(cancellationToken);
                    var connection = new TcpClient();
                    await connection.ConnectAsync(endpoint.Address, endpoint.Port, cancellationToken);
                    _remoteClient = await serverTask;

                    return SocksConnectionResult.Succeeded(connection.GetStream(), (SocksEndpoint)connection.Client.LocalEndPoint);
                });

            var clientOptions1 = new Socks5ClientOptions()
                .WithConnectMethod(ConnectMethod.TCPConnect)
                .WithNoAuthenticationRequired();
            var clientOptions2 = new Socks5ClientOptions()
                .WithConnectMethod(ConnectMethod.TCPConnect)
                .WithUsernamePasswordAuthentication("user123", "password123");

            //Option 1
            {
                var serverTask = _listener.AcceptTcpClientAsync();
                using var client = new TcpClient("127.0.0.1", _localPort);
                using var server = await serverTask;

                using var socksClient = new Socks5ClientProtocol(client.GetStream()) { Options = clientOptions1 };
                using var socksServer = new Socks5ServerProtocol(server.GetStream()) { Options = serverOptions };

                var acceptTask = socksServer.AcceptAsync();
                var connectTask = socksClient.ConnectAsync(AddressType.IPv4, "127.0.0.1", _remotePort);

                await Task.WhenAll(connectTask, acceptTask);

                Assert.That(socksServer.RemoteEndpoint.AddressType, Is.EqualTo(AddressType.IPv4));
                Assert.That(socksServer.RemoteEndpoint.Address, Is.EqualTo("127.0.0.1"));
                Assert.That(socksServer.RemoteEndpoint.Port, Is.EqualTo(_remotePort));

                Assert.That(socksServer.LocalEndpoint, Is.Not.EqualTo(SocksEndpoint.Invalid));

                await ShouldProxyData(socksClient, socksServer);
            }

            //Option 2
            {
                var serverTask = _listener.AcceptTcpClientAsync();
                using var client = new TcpClient("127.0.0.1", _localPort);
                using var server = await serverTask;

                using var socksClient = new Socks5ClientProtocol(client.GetStream()) { Options = clientOptions2 };
                using var socksServer = new Socks5ServerProtocol(server.GetStream()) { Options = serverOptions };

                var acceptTask = socksServer.AcceptAsync();
                var connectTask = socksClient.ConnectAsync(AddressType.IPv4, "127.0.0.1", _remotePort);

                await Task.WhenAll(connectTask, acceptTask);

                Assert.That(socksServer.RemoteEndpoint.AddressType, Is.EqualTo(AddressType.IPv4));
                Assert.That(socksServer.RemoteEndpoint.Address, Is.EqualTo("127.0.0.1"));
                Assert.That(socksServer.RemoteEndpoint.Port, Is.EqualTo(_remotePort));

                Assert.That(socksServer.LocalEndpoint, Is.Not.EqualTo(SocksEndpoint.Invalid));

                await ShouldProxyData(socksClient, socksServer);
            }

        }

        #region Helper
        private async Task ShouldProxyData(Socks5ClientProtocol client, Socks5ServerProtocol server)
        {
            var receiveBuffer = new byte[100000];
            var sendBuffer = new byte[receiveBuffer.Length];
            Random.Shared.NextBytes(sendBuffer);

            Assert.That(_remoteClient, Is.Not.Null);
            Assert.That(server.RemoteStream, Is.TypeOf<NetworkStream>());

            var remotePeer = _remoteClient.GetStream();
            using var tokenSource = new CancellationTokenSource();

            var proxyTask = Task.Run(() => server.ProxyAsync(tokenSource.Token, leaveOpen: true));
            try
            {
                //Async functions
                {
                    //Remote-Peer -> (SocksServer.RemoteSteam <-> SocksServer.LocalSteam) -> Socks-Client
                    await remotePeer.WriteAsync(sendBuffer);
                    await client.Stream.ReadExactlyAsync(receiveBuffer);

                    Assert.That(sendBuffer, Is.EquivalentTo(receiveBuffer));

                    Random.Shared.NextBytes(sendBuffer);

                    //Remote-Peer <- (SocksServer.RemoteSteam <-> SocksServer.LocalSteam) <- Socks-Client
                    await client.Stream.WriteAsync(sendBuffer);
                    await remotePeer.ReadExactlyAsync(receiveBuffer);

                    Assert.That(sendBuffer, Is.EquivalentTo(receiveBuffer));
                }

                //Sync functions
                {
                    //Remote-Peer -> (SocksServer.RemoteSteam <-> SocksServer.LocalSteam) -> Socks-Client
                    remotePeer.Write(sendBuffer);
                    client.Stream.ReadExactly(receiveBuffer);

                    Assert.That(sendBuffer, Is.EquivalentTo(receiveBuffer));

                    Random.Shared.NextBytes(sendBuffer);

                    //Remote-Peer <- (SocksServer.RemoteSteam <-> SocksServer.LocalSteam) <- Socks-Client
                    client.Stream.Write(sendBuffer);
                    remotePeer.ReadExactly(receiveBuffer);

                    Assert.That(sendBuffer, Is.EquivalentTo(receiveBuffer));
                }
            }
            finally
            {
                await tokenSource.CancelAsync();
                await proxyTask;
            }
        }
        #endregion
    }
}
