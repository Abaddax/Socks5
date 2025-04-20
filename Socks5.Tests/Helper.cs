using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Abaddax.Socks5.Tests
{
    internal static class Helper
    {
        public static X509Certificate2 GetSelfSignedCertificate()
        {
            const string certFile = "cert.p12";
            const string password = "";

            if (File.Exists(certFile))
            {
                try
                {
                    var cert = X509CertificateLoader.LoadPkcs12FromFile(certFile, password);
                    if (cert.NotAfter <= DateTime.UtcNow.AddDays(1))
                        throw new Exception("Certificate expires soon");
                    return cert;
                }
                catch (Exception ex)
                {
                    //Generate new cert
                    File.Delete(certFile);
                }
            }

            // Create a new RSA key pair (you can choose ECDsa for elliptic curve keys as well)
            using (RSA rsa = RSA.Create(2048)) // 2048-bit RSA key size (you can adjust the size)
            {
                // Set the certificate's subject name (for example, "CN=localhost")
                var distinguishedName = new X500DistinguishedName($"CN=localhost");

                // Create the certificate request with the RSA key pair
                var certificateRequest = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                // Set the validity period (e.g., 1 year)
                DateTimeOffset notBefore = DateTimeOffset.UtcNow;
                DateTimeOffset notAfter = notBefore.AddYears(1);

                // Create the self-signed certificate
                using X509Certificate2 certificate = certificateRequest.CreateSelfSigned(notBefore, notAfter);

                var bytes = certificate.Export(X509ContentType.Pkcs12, password);

                File.WriteAllBytes(certFile, bytes);

                return X509CertificateLoader.LoadPkcs12FromFile(certFile, password);
            }
        }
    }
}
