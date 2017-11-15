using System.Security.Cryptography.X509Certificates;

namespace Validation.PackageSigning.ValidateCertificate.Tests
{
    public class CertificateVerifierFacts
    {
        public class FactsBase
        {
            public X509Certificate2 RevokedCertificate => null;
        }
    }
}
