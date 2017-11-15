// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NuGet.Services.Validation;

namespace Validation.PackageSigning.ValidateCertificate
{
    public class CertificateVerifier
    {
        public const string CodeSigningCertificateOid = "1.3.6.1.5.5.7.3.3";

        public const X509ChainStatusFlags InvalidCertificateFlags =
            X509ChainStatusFlags.UntrustedRoot |
            X509ChainStatusFlags.RevocationStatusUnknown |
            X509ChainStatusFlags.NotTimeValid |
            X509ChainStatusFlags.NotSignatureValid |
            X509ChainStatusFlags.NotValidForUsage |
            X509ChainStatusFlags.Cyclic |
            X509ChainStatusFlags.InvalidExtension |
            X509ChainStatusFlags.InvalidPolicyConstraints |
            X509ChainStatusFlags.InvalidBasicConstraints |
            X509ChainStatusFlags.InvalidNameConstraints |
            X509ChainStatusFlags.HasNotSupportedNameConstraint |
            X509ChainStatusFlags.HasNotDefinedNameConstraint |
            X509ChainStatusFlags.HasNotPermittedNameConstraint |
            X509ChainStatusFlags.HasExcludedNameConstraint |
            X509ChainStatusFlags.PartialChain |
            X509ChainStatusFlags.CtlNotTimeValid |
            X509ChainStatusFlags.CtlNotSignatureValid |
            X509ChainStatusFlags.CtlNotValidForUsage |
            X509ChainStatusFlags.NoIssuanceChainPolicy |
            X509ChainStatusFlags.NotTimeNested;

        public CertificateVerificationResult Verify(
            X509Certificate2 certificate,
            X509Certificate2[] extraCertificates)
        {
            if (TryBuildChain(certificate, extraCertificates, out X509Chain chain))
            {
                return new CertificateVerificationResult(CertificateStatus.Good);
            }

            // Building the chain failed. Let's determine why.
            var status = DetermineStatusFromInvalidChain(chain);

            if (status == CertificateStatus.Revoked)
            {
                // The end certificate in the chain was revoked. Let's determine when.
                var revocationTime = DetermineRevocationDateFromRevokedChain(chain);

                if (!revocationTime.HasValue)
                {
                    throw new InvalidOperationException("Failed to determine the revocation time of a revoked chain.");
                }

                return new CertificateVerificationResult(revocationTime.Value);
            }
            else
            {
                return new CertificateVerificationResult(status);
            }
        }

        private bool TryBuildChain(X509Certificate2 certificate, X509Certificate2[] extraCertificates, out X509Chain chain)
        {
            chain = new X509Chain();

            // Ensure the signing certificate is a code-signing certificate.
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid(CodeSigningCertificateOid));

            // Allow the chain to use whatever additional extra certificates were provided.
            chain.ChainPolicy.ExtraStore.AddRange(extraCertificates);

            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

            return chain.Build(certificate);
        }

        private CertificateStatus DetermineStatusFromInvalidChain(X509Chain chain)
        {
            var isEndCertificate = true;

            foreach (var chainStatus in chain.ChainStatus)
            {
                if (chainStatus.Status != X509ChainStatusFlags.NoError)
                {
                    if (chainStatus.Status == X509ChainStatusFlags.OfflineRevocation)
                    {
                        return CertificateStatus.Unknown;
                    }

                    if ((chainStatus.Status & X509ChainStatusFlags.Revoked) != 0)
                    {
                        // If a parent certificate has been revoked is what invalidated the end certificate,
                        // ALL signatures that were created using the end certificate should be invalidated.
                        // Hence, the end certificate will be marked as "Invalid".
                        return isEndCertificate
                            ? CertificateStatus.Revoked
                            : CertificateStatus.Invalid;
                    }

                    if ((chainStatus.Status & InvalidCertificateFlags) != 0)
                    {
                        return CertificateStatus.Invalid;
                    }

                    throw new ArgumentException(
                        $"X509Chain contains unknown chain status flag: {chainStatus.Status}, information: {chainStatus.StatusInformation}",
                        nameof(chain));
                }

                isEndCertificate = false;
            }

            throw new ArgumentException("Could not determine X509Chain's status", nameof(chain));
        }

        /// <summary>
        /// Determine the revocation time for the given certificate within the chain.
        /// </summary>
        /// <param name="chain">The chain that contains the certificate.</param>
        /// <param name="certificate">The revoked certificate whose invalidity date will be fetched.</param>
        /// <returns>The certificate's revocation date, or null if a date could not be found.</returns>
        private unsafe DateTime? DetermineRevocationDateFromRevokedChain(X509Chain chain)
        {
            CERT_CHAIN_CONTEXT* pCertChainContext = (CERT_CHAIN_CONTEXT*)(chain.SafeHandle.DangerousGetHandle());
            CERT_SIMPLE_CHAIN* pCertSimpleChain = pCertChainContext->rgpChain[0];

            if (pCertSimpleChain->cElement < 1)
            {
                throw new ArgumentException("Chain must have at least 1 element", nameof(chain));
            }

            CERT_CHAIN_ELEMENT* pChainElement = pCertSimpleChain->rgpElement[0];

            return RevocationDate(pChainElement);
        }

        /// <summary>
        /// Determine the revocation date of a single certificate chain element.
        /// </summary>
        /// <param name="pChainElement">The certificate chain element whose revocation time should be fetched.</param>
        /// <returns>The time that the certificate was revoked, or null if one could not be determined.</returns>
        public unsafe DateTime? RevocationDate(CERT_CHAIN_ELEMENT* pChainElement)
        {
            // Check that the certificate's revocation info is available. It may not be available
            // if the chain was built without revocation checking, or, if the certificate has not
            // been revoked.
            CERT_REVOCATION_INFO* pRevocationInfo = pChainElement->pRevocationInfo;

            if (pRevocationInfo == null
                || pRevocationInfo->dwRevocationResult == CertTrustErrorStatus.CERT_TRUST_NO_ERROR
                || pRevocationInfo->pCrlInfo == null)
            {
                return null;
            }

            FILETIME revocationDate = pRevocationInfo->pCrlInfo->pCrlEntry->RevocationDate;

            return revocationDate.ToDateTime().ToUniversalTime();
        }
    }
}
