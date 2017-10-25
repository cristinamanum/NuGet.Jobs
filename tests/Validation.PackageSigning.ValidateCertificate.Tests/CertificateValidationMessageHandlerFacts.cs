using Microsoft.Extensions.Logging;
using Moq;
using NuGet.Jobs.Validation.PackageSigning.Storage;

namespace Validation.PackageSigning.ValidateCertificate.Tests
{
    public class CertificateValidationMessageHandlerFacts
    {
        private readonly ValidationServiceSetup _setup = new ValidationServiceSetup();

        public sealed class TheHandleAsyncMethod
        {
            // Retries if certificate validation doesn't exist
            // Ends validation if certificate validation isn't what's expected
            // Ends validation if certificate is revoked but certificate validation doesn't have "RevalidateRevokedCertificate"
            // Retries if saving certificate validation fails
            // Ends validation if certificate status is saved to "Good", "Invalid", or "Revoked".
            // Ends validation if certificate status is saved to "Unknown" and maximumValidationFailures is reached.
            // Retries valdiation if certificate status is saved to "Unknown" and maximumValidationFailures is not reached.
        }

        class ValidationServiceSetup
        {
            public IMock<ICertificateStore> CertificateStore { get; }
            public IMock<ICertificateValidationService> CertificateValidationService { get; }

            public CertificateValidationMessageHandler Target { get; }

            public ValidationServiceSetup(int maximumValidationFailures = 5)
            {
                CertificateStore = new Mock<ICertificateStore>();
                CertificateValidationService = new Mock<ICertificateValidationService>();

                var logger = new Mock<ILogger<CertificateValidationMessageHandler>>();

                Target = new CertificateValidationMessageHandler(
                    CertificateStore.Object,
                    CertificateValidationService.Object,
                    logger.Object,
                    maximumValidationFailures);
            }
        }
    }
}
