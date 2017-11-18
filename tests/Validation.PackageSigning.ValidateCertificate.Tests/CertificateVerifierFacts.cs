using System.Security.Cryptography.X509Certificates;
using NuGet.Services.Validation;
using Xunit;

namespace Validation.PackageSigning.ValidateCertificate.Tests
{
    public class CertificateVerifierFacts
    {
        [Fact]
        public void TestRevokedCertificate()
        {
            var target = new CertificateVerifier();

            var result = target.Verify(RevokedCertificate, new X509Certificate2[0]);

            Assert.Equal(CertificateStatus.Revoked, result.Status);
        }

        [Fact]
        public void TestExpiredCertificate()
        {
            var target = new CertificateVerifier();

            var result = target.Verify(ExpiredCertificate, new X509Certificate2[0]);

            Assert.Equal(CertificateStatus.Good, result.Status);
        }

        public X509Certificate2 ExpiredCertificate => new X509Certificate2("C:\\Users\\loshar\\Desktop\\Expired.cer");

        public X509Certificate2 RevokedCertificate => new X509Certificate2("C:\\Users\\loshar\\Desktop\\Revoked.cer");
    }
}
