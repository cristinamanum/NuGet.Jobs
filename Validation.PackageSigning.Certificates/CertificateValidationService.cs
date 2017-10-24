// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Data.Entity;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NuGet.Jobs.Validation.PackageSigning.Messages;
using NuGet.Services.Validation;

namespace Validation.PackageSigning.ValidateCertificate
{
    internal class CertificateValidationService : ICertificateValidationService
    {
        private readonly IValidationEntitiesContext _context;
        private readonly ILogger<CertificateValidationService> _logger;
        private readonly int _maximumValidationFailures;

        public CertificateValidationService(
            IValidationEntitiesContext context,
            ILogger<CertificateValidationService> logger,
            int maximumValidationFailures)
        {
            _context = context;
            _maximumValidationFailures = maximumValidationFailures;
            _logger = logger;
        }

        public Task<CertificateValidation> FindCertificateValidation(CertificateValidationMessage message)
        {
            return _context
                        .CertificateValidations
                        .Where(v => v.ValidationId == message.ValidationId && v.CertificateKey == message.CertificateKey)
                        .Include(v => v.Certificate)
                        .FirstOrDefaultAsync();
        }

        public Task<CertificateVerificationResult> Verify(X509Certificate2 certificate)
        {
            // TODO: This will be implemented in a separate change!
            throw new NotImplementedException();
        }

        public async Task SaveResultAsync(CertificateValidation validation, CertificateVerificationResult result)
        {
            // TODO: If certificate entity is revoked and result isn't revoked, LOG WARNING!
            switch (result.Status)
            {
                case CertificateStatus.Good:
                    SaveGoodCertificateStatusAsync(validation);
                    break;

                case CertificateStatus.Invalid:
                    SaveInvalidCertificateStatusAsync(validation);
                    break;

                case CertificateStatus.Revoked:
                    SaveRevokedCertificateStatusAsync(validation, result.RevocationTime.Value);
                    break;

                case CertificateStatus.Unknown:
                    SaveUnknownCertificateStatusAsync(validation);
                    break;

                default:
                    _logger.LogError(
                        $"Unknown {nameof(CertificateStatus)} value: {{CertificateStatus}}, throwing to retry",
                        result.Status);

                    throw new InvalidOperationException($"Unknown {nameof(CertificateStatus)} value: {result.Status}");
            }

            await _context.SaveChangesAsync();
        }

        private void SaveGoodCertificateStatusAsync(CertificateValidation validation)
        {
            validation.Certificate.Status = CertificateStatus.Good;
            validation.Certificate.StatusUpdateTime = null;
            validation.Certificate.NextStatusUpdateTime = null;
            validation.Certificate.LastVerificationTime = DateTime.UtcNow;
            validation.Certificate.RevocationTime = null;
            validation.Certificate.ValidationFailures = 0;

            validation.Status = CertificateStatus.Good;
        }

        private void SaveInvalidCertificateStatusAsync(CertificateValidation validation)
        {
            validation.Certificate.Status = CertificateStatus.Invalid;
            validation.Certificate.StatusUpdateTime = null;
            validation.Certificate.NextStatusUpdateTime = null;
            validation.Certificate.LastVerificationTime = DateTime.UtcNow;
            validation.Certificate.RevocationTime = null;
            validation.Certificate.ValidationFailures = 0;

            validation.Status = CertificateStatus.Invalid;

            foreach (var signature in validation.Certificate.PackageSignatures)
            {
                if (signature.Status != PackageSignatureStatus.InGracePeriod)
                {
                    // TODO: ALERT - previously okay package is now invalid!
                }

                signature.Status = PackageSignatureStatus.Invalid;
                signature.PackageSigningState.SigningStatus = PackageSigningStatus.Invalid;
            }
        }

        private void SaveRevokedCertificateStatusAsync(CertificateValidation validation, DateTime revocationTime)
        {
            validation.Certificate.Status = CertificateStatus.Revoked;
            validation.Certificate.StatusUpdateTime = null;
            validation.Certificate.NextStatusUpdateTime = null;
            validation.Certificate.LastVerificationTime = DateTime.UtcNow;
            validation.Certificate.RevocationTime = revocationTime.ToUniversalTime();
            validation.Certificate.ValidationFailures = 0;

            validation.Status = CertificateStatus.Revoked;

            foreach (var signature in validation.Certificate.PackageSignatures)
            {
                // TODO: If this is the timestamp authority certificate, ALWAYS revoke the package!!
                if (signature.TrustedTimestamps.Any(t => t.Value < revocationTime)) continue;

                if (signature.Status != PackageSignatureStatus.InGracePeriod)
                {
                    // ALERT - previously okay package is now invalid!
                }

                signature.Status = PackageSignatureStatus.Invalid;
                signature.PackageSigningState.SigningStatus = PackageSigningStatus.Invalid;
            }
        }

        private void SaveUnknownCertificateStatusAsync(CertificateValidation validation)
        {
            validation.Certificate.ValidationFailures++;

            if (validation.Certificate.ValidationFailures >= _maximumValidationFailures)
            {
                // The maximum number of validation failures has been reached. The certificate's
                // validation should not be retried as a NuGet Admin will need to investigate the issues.
                // If the certificate is found to be invalid, the Admin will need to invalidate packages
                // and timestamps that depend on this certificate!
                validation.Certificate.Status = CertificateStatus.Invalid;
                validation.Certificate.LastVerificationTime = DateTime.UtcNow;

                validation.Status = CertificateStatus.Invalid;

                // TODO: ALERT
                // TODO: This should be retried!
            }
        }
    }
}
