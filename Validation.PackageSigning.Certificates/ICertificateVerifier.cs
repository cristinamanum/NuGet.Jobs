// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using NuGet.Services.Validation;

namespace Validation.PackageSigning.ValidateCertificate
{
    /// <summary>
    /// The result of a <see cref="X509Certificate2"/> verification by the
    /// <see cref="ICertificateVerifier"/>.
    /// </summary>
    public class CertificateVerification
    {
        /// <summary>
        /// The status of the <see cref="X509Certificate2"/>.
        /// </summary>
        public CertificateStatus Status { get; set; }

        /// <summary>
        /// The time at which the <see cref="X509Certificate2"/> was revoked. Null unless
        /// <see cref="Status"/> is <see cref="CertificateStatus.Revoked"/>.
        /// </summary>
        public DateTime? RevocationTime { get; set; }
    }

    /// <summary>
    /// The <see cref="X509Certificate2"/> verifier.
    /// </summary>
    public interface ICertificateVerifier
    {
        /// <summary>
        /// Verify the certificate. Ensures the certificate is well-formed
        /// and does online revocation checking.
        /// </summary>
        /// <param name="certificate">The certificate to validate.</param>
        /// <returns>The result of the verification.</returns>
        Task<CertificateVerification> Verify(X509Certificate2 certificate);
    }
}