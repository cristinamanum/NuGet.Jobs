// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NuGet.Jobs.Validation.PackageSigning.Messages;
using NuGet.Services.Validation;

namespace Validation.PackageSigning.ValidateCertificate
{
    public class CertificateValidationService : ICertificateValidationService
    {
        private readonly IValidationEntitiesContext _context;
        private readonly IAlertingService _alertingService;
        private readonly ILogger<CertificateValidationService> _logger;
        private readonly int _maximumValidationFailures;

        public CertificateValidationService(
            IValidationEntitiesContext context,
            IAlertingService alertingService,
            ILogger<CertificateValidationService> logger,
            int maximumValidationFailures)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _alertingService = alertingService ?? throw new ArgumentNullException(nameof(alertingService));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            _maximumValidationFailures = maximumValidationFailures;
        }

        public Task<CertificateValidation> FindCertificateValidationAsync(CertificateValidationMessage message)
        {
            return _context
                        .CertificateValidations
                        .Where(v => v.ValidationId == message.ValidationId && v.CertificateKey == message.CertificateKey)
                        .Include(v => v.Certificate)
                        .FirstOrDefaultAsync();
        }

        public Task<CertificateVerificationResult> VerifyAsync(X509Certificate2 certificate)
        {
            // TODO: This will be implemented in a separate change!
            throw new NotImplementedException();
        }

        public async Task<bool> TrySaveResultAsync(CertificateValidation validation, CertificateVerificationResult result)
        {
            if (validation.Certificate.Status == CertificateStatus.Revoked && result.Status != CertificateStatus.Revoked)
            {
                _logger.LogWarning(
                    "Updating previously revoked certificate {CertificateThumbprint} to status {NewStatus}",
                    validation.Certificate.Thumbprint,
                    result.Status);
            }

            switch (result.Status)
            {
                case CertificateStatus.Good:
                    SaveGoodCertificateStatus(validation);
                    break;

                case CertificateStatus.Invalid:
                    await SaveInvalidCertificateStatusAsync(validation);
                    break;

                case CertificateStatus.Revoked:
                    await SaveRevokedCertificateStatusAsync(validation, result.RevocationTime.Value);
                    break;

                case CertificateStatus.Unknown:
                    SaveUnknownCertificateStatus(validation);
                    break;

                default:
                    _logger.LogError(
                        $"Unknown {nameof(CertificateStatus)} value: {{CertificateStatus}}, throwing to retry",
                        result.Status);

                    throw new InvalidOperationException($"Unknown {nameof(CertificateStatus)} value: {result.Status}");
            }

            try
            {
                await _context.SaveChangesAsync();

                return true;
            }
            catch (DbUpdateConcurrencyException)
            {
                _logger.LogError(
                    "Failed to update certificate {CertificateThumbprint} to status {NewStatus}",
                    validation.Certificate.Thumbprint,
                    result.Status);

                return false;
            }
        }

        private void SaveGoodCertificateStatus(CertificateValidation validation)
        {
            // TODO: StatusUpdateTime and NextStatusUpdateTime!
            validation.Certificate.Status = CertificateStatus.Good;
            validation.Certificate.StatusUpdateTime = null;
            validation.Certificate.NextStatusUpdateTime = null;
            validation.Certificate.LastVerificationTime = DateTime.UtcNow;
            validation.Certificate.RevocationTime = null;
            validation.Certificate.ValidationFailures = 0;

            validation.Status = CertificateStatus.Good;
        }

        private async Task SaveInvalidCertificateStatusAsync(CertificateValidation validation)
        {
            // TODO: StatusUpdateTime and NextStatusUpdateTime!
            validation.Certificate.Status = CertificateStatus.Invalid;
            validation.Certificate.StatusUpdateTime = null;
            validation.Certificate.NextStatusUpdateTime = null;
            validation.Certificate.LastVerificationTime = DateTime.UtcNow;
            validation.Certificate.RevocationTime = null;
            validation.Certificate.ValidationFailures = 0;

            validation.Status = CertificateStatus.Invalid;

            var signatures = await FindSignatures(validation.Certificate);

            foreach (var signature in signatures)
            {
                if (signature.Status != PackageSignatureStatus.InGracePeriod)
                {
                    _logger.LogWarning(
                        "Signature {SignatureKey} SHOULD be invalidated by NuGet Admin due to invalid certificate {CertificateThumbprint}. Firing alert...",
                        signature.Key,
                        validation.Certificate.Thumbprint);

                    _alertingService.FirePackageSignatureShouldBeInvalidatedAlert(signature);
                }

                signature.Status = PackageSignatureStatus.Invalid;
                signature.PackageSigningState.SigningStatus = PackageSigningStatus.Invalid;
            }
        }

        private async Task SaveRevokedCertificateStatusAsync(CertificateValidation validation, DateTime revocationTime)
        {
            validation.Certificate.Status = CertificateStatus.Revoked;
            validation.Certificate.StatusUpdateTime = null;
            validation.Certificate.NextStatusUpdateTime = null;
            validation.Certificate.LastVerificationTime = DateTime.UtcNow;
            validation.Certificate.RevocationTime = revocationTime.ToUniversalTime();
            validation.Certificate.ValidationFailures = 0;

            validation.Status = CertificateStatus.Revoked;

            var signatures = await FindSignatures(validation.Certificate);

            foreach (var signature in signatures)
            {
                // A revoked certificate does not necessarily invalidate a dependent signature. Skip signatures
                // that should NOT be invalidated.
                if (!RevokedCertificateInvalidatesSignature(validation.Certificate, signature))
                {
                    continue;
                }

                if (signature.Status != PackageSignatureStatus.InGracePeriod)
                {
                    _logger.LogWarning(
                        "Signature {SignatureKey} SHOULD be invalidated by NuGet Admin due to revoked certificate {CertificateThumbprint}. Firing alert...",
                        signature.Key,
                        validation.Certificate.Thumbprint);

                    _alertingService.FirePackageSignatureShouldBeInvalidatedAlert(signature);
                }

                signature.Status = PackageSignatureStatus.Invalid;
                signature.PackageSigningState.SigningStatus = PackageSigningStatus.Invalid;
            }
        }

        private void SaveUnknownCertificateStatus(CertificateValidation validation)
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

                _logger.LogWarning(
                    "Certificate {CertificateThumbprint} has reached maximum of {MaximumValidationFailures} failed validation attempts, " +
                    "and requires manual investigation by NuGet Admin. Firing alert...",
                    validation.Certificate.Thumbprint,
                    _maximumValidationFailures);

                _alertingService.FireUnableToValidateCertificateAlert(validation.Certificate);
            }
        }

        /// <summary>
        /// Find all package signatures that depend on the given certificate.
        /// </summary>
        /// <param name="certificate">The certificate whose signatures should be found.</param>
        /// <returns>The signatures that depend on the given certificate.</returns>
        private Task<List<PackageSignature>> FindSignatures(Certificate certificate)
        {
            return _context
                        .PackageSignatures
                        .Include(s => s.TrustedTimestamps)
                        .Where(s => SignatureDependsOnCertificate(s, certificate))
                        .ToListAsync();
        }

        /// <summary>
        /// Determines whether a signature depends on the given certificate.
        /// </summary>
        /// <param name="signature">The signature that may depend on the certificate.</param>
        /// <param name="certificate">The certificate that the signature may depend on.</param>
        /// <returns>Whether the signature depend on the given certificate.</returns>
        private bool SignatureDependsOnCertificate(PackageSignature signature, Certificate certificate)
        {
            if (signature.Certificate.Thumbprint == certificate.Thumbprint)
            {
                return true;
            }

            return signature.TrustedTimestamps.Any(t => t.Certificate.Thumbprint == certificate.Thumbprint);
        }

        /// <summary>
        /// Determines whether a revoked certificate should invalidate the signature.
        /// </summary>
        /// <param name="certificate">The revoked certificate.</param>
        /// <param name="signature">The signature that may be invalidated.</param>
        /// <returns>Whether the signature should be invalidated.</returns>
        private bool RevokedCertificateInvalidatesSignature(Certificate certificate, PackageSignature signature)
        {
            // The signature may depend on a certificate in one of two ways: either the signature itself was signed with
            // the certificate, or, the trusted timestamp authority used the certificate to sign its timestamp. Note that
            // it is "possible" that both the signature and the trusted timestamp depend on the certificate.
            if (signature.Certificate.Thumbprint == certificate.Thumbprint)
            {
                // The signature was signed using the certificate. Ensure that none of the trusted timestamps indicate
                // that the signature was created after the certificate's invalidity date begins.
                if (signature.TrustedTimestamps.Any(t => certificate.RevocationTime <= t.Value))
                {
                    return true;
                }
            }

            // If any of the signature's trusted timestamps depend on the revoked certificate,
            // the signature should be revoked.
            return signature.TrustedTimestamps.Any(t => t.Certificate == certificate);
        }
    }
}
