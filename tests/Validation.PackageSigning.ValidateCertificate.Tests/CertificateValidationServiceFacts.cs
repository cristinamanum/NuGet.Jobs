using Microsoft.Extensions.Logging;
using Moq;
using NuGet.Services.Validation;

namespace Validation.PackageSigning.ValidateCertificate.Tests
{
    public class CertificateValidationServiceFacts
    {
        private IMock<IValidationEntitiesContext> _context;
        private IMock<IAlertingService> _alertingService;

        private CertificateValidationService _target;

        public class TheFindCertificateValidationAsyncMethod
        {
            // Returns null if no results
            // Returns result
        }

        public class TheVerifyAsyncMethod
        {
            // TODO
        }

        public class TheTrySaveResultAsyncMethod
        {
            // Verify Good Status save
            // Invalid status should invalidate all dependent signatures (signed w/ certificate + or timestamp depends on cert)
            // Revoked status should invalidate some signatures (all signed w/ certificate before invalidity + or timestamp depends on cert)
            // Unknown save
            // Unknown reaches maximum threshold should alert
        }

        public CertificateValidationServiceFacts()
        {
            _context = new Mock<IValidationEntitiesContext>();
            _alertingService = new Mock<IAlertingService>();

            var logger = new Mock<ILogger<CertificateValidationService>>();

            _target = new CertificateValidationService(
                _context.Object,
                _alertingService.Object,
                logger.Object,
                maximumValidationFailures: 5);
        }
    }
}
