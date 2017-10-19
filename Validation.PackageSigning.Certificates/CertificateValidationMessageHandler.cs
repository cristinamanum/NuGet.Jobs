// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Data.Entity;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NuGet.Jobs.Validation.PackageSigning;
using NuGet.Jobs.Validation.PackageSigning.Messages;
using NuGet.Services.ServiceBus;
using NuGet.Services.Validation;

namespace Validation.PackageSigning.ValidateCertificate
{
    /// <summary>
    /// The handler for <see cref="CertificateValidationMessage"/>. Upon receiving a message,
    /// this will validate a <see cref="X509Certificate2"/> and perform online revocation checks.
    /// </summary>
    public class CertificateValidationMessageHandler : IMessageHandler<CertificateValidationMessage>
    {
        private const int DefaultMaximumValidationFailures = 5;

        private readonly IValidationEntitiesContext _context;
        private readonly ICertificateStore _certificateStore;
        private readonly ICertificateVerifier _certificateVerifier;
        private readonly ILogger<CertificateValidationMessageHandler> _logger;
        private readonly int _maximumValidationFailures;

        public CertificateValidationMessageHandler(
            IValidationEntitiesContext context,
            ICertificateStore certificateStore,
            ICertificateVerifier certificateVerifier,
            ILogger<CertificateValidationMessageHandler> logger,
            int maximumValidationFailures = DefaultMaximumValidationFailures)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _certificateStore = certificateStore ?? throw new ArgumentNullException(nameof(certificateStore));
            _certificateVerifier = certificateVerifier ?? throw new ArgumentNullException(nameof(certificateVerifier));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            _maximumValidationFailures = maximumValidationFailures;
        }

        /// <summary>
        /// Perform the certificate validation request, including online revocation checks.
        /// </summary>
        /// <param name="message">The message requesting the certificate validation.</param>
        /// <returns>Whether the validation completed. If false, the validation should be retried later.</returns>
        public async Task<bool> HandleAsync(CertificateValidationMessage message)
        {
            // Find the certificate validation entity that matches this message.
            var validation = await _context
                                        .CertificateValidations
                                        .Where(v => v.ValidationId == message.ValidationId && v.CertificateKey == message.CertificateKey)
                                        .Include(v => v.Certificate)
                                        .FirstOrDefaultAsync();

            if (validation == null)
            {
                _logger.LogInformation(
                    "Could not find a certificate validation entity, requeueing (certificate: {CertificateKey} validation: {ValidationId})",
                    message.CertificateKey,
                    message.ValidationId);

                return false;
            }

            if (validation.Status != null)
            {
                // A certificate validation should be queued with a Status of null, and once the certificate validation
                // completes, the Status should be updated to a non-null value. Hence, the Status here SHOULD be null.
                // A non-null Status may indicate message duplication.
                _logger.LogError(
                    "Invalid certificate validation entity's status, dropping message (certificate: {CertificateThumbprint} validation: {ValidationId})",
                    validation.Certificate.Thumbprint,
                    validation.ValidationId);

                return true;
            }

            if (validation.Certificate.Status == CertificateStatus.Revoked)
            {
                if (message.RevalidateRevokedCertificate)
                {
                    _logger.LogWarning(
                        "Revalidating certificate that is known to be revoked " +
                        "(certificate: {CertificateThumbprint} validation: {ValidationId})",
                        validation.Certificate.Thumbprint,
                        validation.ValidationId);
                }
                else
                {
                    // Do NOT revalidate a certificate that is known to be revoked unless explicitly told to!
                    // Certificate Authorities are not required to keep a certificate's revocation information
                    // forever, therefore, revoked certificates should only be revalidated in special cases.
                    _logger.LogError(
                        "Certificate known to be revoked MUST be validated with the " +
                        $"{nameof(CertificateValidationMessage.RevalidateRevokedCertificate)} flag enabled " +
                        "(certificate: {CertificateThumbprint} validation: {ValidationId})",
                        validation.Certificate.Thumbprint,
                        validation.ValidationId);

                    return true;
                }
            }

            // Download and verify the certificate.
            var certificate = await _certificateStore.Load(validation.Certificate.Thumbprint);
            var result = await _certificateVerifier.Verify(certificate);

            // TODO: If certificate entity is revoked and result isn't revoked, LOG WARNING!

            switch (result.Status)
            {
                case CertificateStatus.Good:
                    return await HandleGoodCertificateStatusAsync(validation);

                case CertificateStatus.Invalid:
                    return await HandleInvalidCertificateStatusAsync(validation);

                case CertificateStatus.Revoked:
                    return await HandleRevokedCertificateStatusAsync(validation, result.RevocationTime.Value);

                case CertificateStatus.Unknown:
                    return await HandleUnknownCertificateStatusAsync(validation);

                default:
                    _logger.LogError(
                        $"Unknown {nameof(CertificateStatus)} value: {{CertificateStatus}}, throwing to retry",
                        result.Status);

                    throw new InvalidOperationException($"Unknown {nameof(CertificateStatus)} value: {result.Status}");
            }
        }

        private async Task<bool> HandleGoodCertificateStatusAsync(CertificateValidation validation)
        {
            validation.Certificate.Status = CertificateStatus.Good;
            validation.Certificate.StatusUpdateTime = null;
            validation.Certificate.NextStatusUpdateTime = null;
            validation.Certificate.LastVerificationTime = DateTime.UtcNow;
            validation.Certificate.RevocationTime = null;
            validation.Certificate.ValidationFailures = 0;

            validation.Status = CertificateStatus.Good;

            await _context.SaveChangesAsync();

            return true;
        }

        private async Task<bool> HandleInvalidCertificateStatusAsync(CertificateValidation validation)
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

            await _context.SaveChangesAsync();

            return true;
        }

        private async Task<bool> HandleRevokedCertificateStatusAsync(CertificateValidation validation, DateTime revocationTime)
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

            await _context.SaveChangesAsync();

            return true;
        }

        private async Task<bool> HandleUnknownCertificateStatusAsync(CertificateValidation validation)
        {
            validation.Certificate.ValidationFailures++;

            if (validation.Certificate.ValidationFailures >= _maximumValidationFailures)
            {
                // The maximum number of validation failures has been reached. The certificate's
                // validation should not be retried as an engineer will need to investigate the issues.
                validation.Certificate.Status = CertificateStatus.Unknown;
                validation.Certificate.LastVerificationTime = DateTime.UtcNow;

                validation.Status = CertificateStatus.Unknown;

                // TODO: ALERT

                // Save the current validation state and consume the service bus message.
                await _context.SaveChangesAsync();

                return true;
            }
            else
            {
                // Save the current validation state but do not consume the service bus message so
                // so that this certificate validation is tried again.
                await _context.SaveChangesAsync();

                return false;
            }
        }
    }
}