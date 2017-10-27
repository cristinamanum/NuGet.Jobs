﻿// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using NuGet.Jobs.Validation.PackageSigning.Messages;
using NuGet.Services.Validation;

namespace Validation.PackageSigning.ValidateCertificate
{
    /// <summary>
    /// The result of a <see cref="X509Certificate2"/> verification by the
    /// <see cref="ICertificateVerifier"/>.
    /// </summary>
    public class CertificateVerificationResult
    {
        /// <summary>
        /// Create a new non-revoked certificate verification result.
        /// </summary>
        /// <param name="status">The status of the <see cref="X509Certificate2"/></param>
        /// <param name="revocationTime">The time of </param>
        public CertificateVerificationResult(CertificateStatus status)
        {
            if (status == CertificateStatus.Revoked)
            {
                throw new ArgumentException("Provide a revocation date for a revoked certificate result.", nameof(status));
            }

            Status = status;
        }

        /// <summary>
        /// Create a new revoked certificate verification result.
        /// </summary>
        /// <param name="revocationTime">The start of the certificate's invalidity period.</param>
        public CertificateVerificationResult(DateTime revocationTime)
        {
            Status = CertificateStatus.Revoked;
            RevocationTime = revocationTime;
        }

        /// <summary>
        /// The status of the <see cref="X509Certificate2"/>.
        /// </summary>
        public CertificateStatus Status { get; }

        /// <summary>
        /// The time at which the <see cref="X509Certificate2"/> was revoked. Null unless
        /// <see cref="Status"/> is <see cref="CertificateStatus.Revoked"/>.
        /// </summary>
        public DateTime? RevocationTime { get; }
    }

    public interface ICertificateValidationService
    {
        /// <summary>
        /// Find the <see cref="CertificateValidation"/> for the given <see cref="CertificateValidationMessage"/>.
        /// </summary>
        /// <param name="message">The message requesting a certificate validation.</param>
        /// <returns>The entity representing the certificate validation's state, or null if one could not be found.</returns>
        Task<CertificateValidation> FindCertificateValidationAsync(CertificateValidationMessage message);

        /// <summary>
        /// Verify the certificate. Ensures the certificate is well-formed
        /// and does online revocation checking.
        /// </summary>
        /// <param name="certificate">The certificate to validate.</param>
        /// <returns>The result of the verification.</returns>
        Task<CertificateVerificationResult> VerifyAsync(X509Certificate2 certificate);

        /// <summary>
        /// Update the requested <see cref="CertificateValidation"/> with the <see cref="CertificateVerificationResult"/>.
        /// This may kick off alerts if packages are invalidated!
        /// </summary>
        /// <param name="validation">The validation that should be updated.</param>
        /// <param name="result">Whether the save operation was successful.</param>
        Task<bool> TrySaveResultAsync(CertificateValidation validation, CertificateVerificationResult result);
    }
}