using Abaddax.Socks5.Helper;
using Abaddax.Socks5.Protocol;
using Abaddax.Socks5.Protocol.Enums;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using static Abaddax.Socks5.Helper.Socks5ConnectionLog;

namespace Abaddax.Socks5.Tests
{
    [NonParallelizable]
    public class Socks5ConnectionLogTests
    {
        const ushort _localPort = 61080;
        const ushort _remotePort = 54321;

        TcpListener _listener;
        Socks5ClientOptions _clientOptions;
        Socks5ServerOptions _serverOptions;

        [SetUp]
        public void Setup()
        {
            _listener = new TcpListener(IPAddress.Loopback, _localPort);
            _listener.Start();

            _clientOptions = new Socks5ClientOptions()
                .WithNoAuthenticationRequired()
                .WithConnectMethod(ConnectMethod.TCPConnect);
            _serverOptions = new Socks5ServerOptions()
                .WithNoAuthenticationRequired()
                .WithConnectionHandler(async (method, endpoint, _) =>
                {
                    if (method != ConnectMethod.TCPConnect)
                        return SocksConnectionResult.Failed(ConnectCode.NotAllowedByRuleset);
                    return SocksConnectionResult.Succeeded(new MemoryStream(), endpoint with { Port = 12345 });
                });
        }

        [TearDown]
        public void Teardown()
        {
            _listener.Dispose();
        }


        [Test]
        public async Task ShouldConnectWithLoggedConnections()
        {
            var serverTask = _listener.AcceptTcpClientAsync();
            using var client = new TcpClient("127.0.0.1", _localPort);
            using var server = await serverTask;

            ConcurrentQueue<Socks5ConnectionLog> clientConnectionLog = new();
            ConcurrentQueue<Socks5ConnectionLog> serverConnectionLog = new();

            using var socksClient = _clientOptions.CreateLoggedSocksClient(client.GetStream(), out var clientObservable);
            using var socksServer = _serverOptions.CreateLoggedSocksServer(server.GetStream(), out var serverObservable);

            {
                using var clientObserver = clientObservable.Subscribe(x => clientConnectionLog.Enqueue(x));
                using var serverObserver = serverObservable.Subscribe(x => serverConnectionLog.Enqueue(x));

                var acceptTask = socksServer.AcceptAsync();
                var connectTask = socksClient.ConnectAsync(AddressType.IPv4, "127.0.0.1", _remotePort);

                await Task.WhenAll(connectTask, acceptTask);

                Assert.That(socksClient.LocalEndpoint, Is.Not.EqualTo(SocksEndpoint.Invalid));
                Assert.That(socksServer.LocalEndpoint, Is.Not.EqualTo(SocksEndpoint.Invalid));
            }

            Assert.That(clientConnectionLog, Has.Count.EqualTo(4));
            Assert.That(serverConnectionLog, Has.Count.EqualTo(4));

            for (int i = 0; i < 4; i++)
            {
                Assert.That(clientConnectionLog.TryDequeue(out var clientLog), Is.True);
                Assert.That(serverConnectionLog.TryDequeue(out var serverLog), Is.True);

                var role = i % 2 == 0 ? ConnectionRole.Client : ConnectionRole.Server;
                Assert.That(clientLog.Role, Is.EqualTo(role));
                Assert.That(serverLog.Role, Is.EqualTo(role));

                Assert.That(clientLog.Data, Is.EquivalentTo(serverLog.Data));
            }
        }
    }
}
