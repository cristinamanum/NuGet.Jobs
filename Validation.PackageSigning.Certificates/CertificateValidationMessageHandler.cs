// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Data.Entity;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NuGet.Jobs.Validation.PackageSigning.Messages;
using NuGet.Jobs.Validation.PackageSigning.Storage;
using NuGet.Services.ServiceBus;
using NuGet.Services.Validation;

namespace Validation.PackageSigning.ValidateCertificate
{
    /// <summary>
    /// The handler for <see cref="CertificateValidationMessage"/>. Upon receiving a message,
    /// this will validate a <see cref="X509Certificate2"/> and perform online revocation checks.
    /// </summary>
    internal sealed class CertificateValidationMessageHandler : IMessageHandler<CertificateValidationMessage>
    {
        private const int DefaultMaximumValidationFailures = 5;

        private readonly ICertificateStore _certificateStore;
        private readonly ICertificateValidationService _certificateValidationService;
        private readonly ILogger<CertificateValidationMessageHandler> _logger;
        private readonly int _maximumValidationFailures;

        public CertificateValidationMessageHandler(
            ICertificateStore certificateStore,
            ICertificateValidationService certificateValidationService,
            ILogger<CertificateValidationMessageHandler> logger,
            int maximumValidationFailures = DefaultMaximumValidationFailures)
        {
            _certificateStore = certificateStore ?? throw new ArgumentNullException(nameof(certificateStore));
            _certificateValidationService = certificateValidationService ?? throw new ArgumentNullException(nameof(certificateValidationService));
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
            var validation = await _certificateValidationService.FindCertificateValidation(message);

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
            var result = await _certificateValidationService.Verify(certificate);

            await _certificateValidationService.SaveResultAsync(validation, result);

            return HasValidationCompleted(validation, result);
        }

        private bool HasValidationCompleted(CertificateValidation validation, CertificateVerificationResult result)
        {
            if (result.Status != CertificateStatus.Unknown) return true;

            if (validation.Certificate.ValidationFailures >= _maximumValidationFailures)
            {
                // TODO: LogWarning!
                return true;
            }
            else
            {
                // TODO: LogWarning!
                return false;
            }
        }
    }
}