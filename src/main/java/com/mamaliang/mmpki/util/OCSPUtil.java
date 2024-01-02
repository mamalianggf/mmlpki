//package com.mamaliang.mmpki.ocsp.util;
//
//import org.bouncycastle.cert.ocsp.OCSPReq;
//import org.bouncycastle.cert.ocsp.OCSPResp;
//import org.bouncycastle.cert.ocsp.RespID;
//
///**
// * rfc 6960
// *
// * @author gaof
// * @date 2023/11/29
// */
//public class OCSPUtil {
//
//    private OCSPResp doProcessOCSPRequest(OCSPReq ocspReq) throws OCSPException {
//
//        RespID
//
//        BasicOCSPRespBuilder responseBuilder = new BasicOCSPRespBuilder(responderID);
//
//        checkForValidRequest(ocspReq);
//
//        // Add appropriate extensions
//        Collection<Extension> responseExtensions = new ArrayList<>();
//        //nonce
//        Extension nonceExtension = ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
//        if (nonceExtension != null) {
//            responseExtensions.add(nonceExtension);
//        }
//        if (rejectUnknown) {
//            responseExtensions.add(
//                    new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_extended_revoke, false, new byte[]{})
//            );
//        }
//
//        Extension[] extensions = responseExtensions.toArray(new Extension[responseExtensions.size()]);
//        responseBuilder.setResponseExtensions(new Extensions(extensions));
//
//        // Check that each request is valid and put the appropriate response in the builder
//        Req[] requests = ocspReq.getRequestList();
//        for (Req request : requests) {
//            addResponse(responseBuilder, request);
//        }
//        return buildAndSignResponse(responseBuilder);
//    }
//
//    /**
//     * Checks for a valid request and throws a BadRequestException with the OCSP response if not valid
//     *
//     * @param ocspReq The request
//     * @throws BadRequestException with the OCSP response if the request was malformed
//     */
//    private void checkForValidRequest(OCSPReq ocspReq) throws OCSPException {
//        if (ocspReq == null) {
//            throw new BadRequestException("Could not find a request in the payload!",
//                    Response.status(Response.Status.BAD_REQUEST).entity(
//                            new OCSPRespBuilder().build(OCSPRespBuilder.MALFORMED_REQUEST, null)
//                    ).build()
//            );
//        }
//        // Check signature if present
//        if (ocspReq.isSigned() && !isSignatureValid(ocspReq)) {
//            throw new BadRequestException("Your signature was invalid!",
//                    Response.status(Response.Status.BAD_REQUEST).entity(
//                            new OCSPRespBuilder().build(OCSPRespBuilder.MALFORMED_REQUEST, null)
//                    ).build()
//            );
//        }
//    }
//
//    /**
//     * Checks to see if the signature in the OCSP request is valid.
//     *
//     * @param ocspReq The OCSP request.
//     * @return {@code true} if the signature is valid, {@code false} otherwise.
//     */
//    private boolean isSignatureValid(OCSPReq ocspReq) throws OCSPException {
//        try {
//            return ocspReq.isSignatureValid(
//                    new JcaContentVerifierProviderBuilder() // Can we reuse this builder?
//                            .setProvider("BC")
//                            .build(ocspReq.getCerts()[0])
//            );
//        } catch (CertificateException | OperatorCreationException e) {
//            LOG.warn("Could not read signature!", e);
//            return false;
//        }
//    }
//
//    /**
//     * Adds response for specific cert OCSP request
//     *
//     * @param responseBuilder The builder containing the full response
//     * @param request The specific cert request
//     */
//    private void addResponse(BasicOCSPRespBuilder responseBuilder, Req request) throws OCSPException{
//        CertificateID certificateID = request.getCertID();
//
//        // Build Extensions
//        Extensions extensions = new Extensions(new Extension[]{});
//        Extensions requestExtensions = request.getSingleRequestExtensions();
//        if (requestExtensions != null) {
//            Extension nonceExtension = requestExtensions.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
//            if (nonceExtension != null) {
//                extensions = new Extensions(nonceExtension);
//            }
//        }
//
//        // Check issuer
//        boolean matchesIssuer = certificateID.matchesIssuer(issuingCertificate, digestCalculatorProvider);
//
//        if (!matchesIssuer) {
//            addResponseForCertificateRequest(responseBuilder,
//                    certificateID,
//                    new OCSPCertificateStatusWrapper(getUnknownStatus(),
//                            DateTime.now(),
//                            DateTime.now().plusSeconds(certificateManager.getRefreshSeconds())),
//                    extensions);
//
//        } else {
//            CertificateSummary certificateSummary = certificateManager.getSummary(certificateID.getSerialNumber());
//
//            addResponseForCertificateRequest(responseBuilder,
//                    request.getCertID(),
//                    getOCSPCertificateStatus(certificateSummary),
//                    extensions);
//        }
//    }
//
//    private void addResponseForCertificateRequest(BasicOCSPRespBuilder responseBuilder,
//                                                  CertificateID certificateID,
//                                                  OCSPCertificateStatusWrapper status,
//                                                  Extensions extensions) {
//        responseBuilder.addResponse(certificateID,
//                status.getCertificateStatus(),
//                status.getThisUpdateDate(),
//                status.getNextUpdateDate(),
//                extensions);
//    }
//
//    /**
//     * Gets the OCSP Certificate Status Wrapper with the Certificate Status (good, revoked, unknown),
//     * the updated date, and the next update date.
//     *
//     * @param summary The certificate summary
//     * @return The status wrapper
//     */
//    private OCSPCertificateStatusWrapper getOCSPCertificateStatus(CertificateSummary summary) {
//        CertificateStatus status;
//        switch (summary.getStatus()) {
//            case VALID:
//                status = CertificateStatus.GOOD;
//                break;
//            case REVOKED:
//                status = new RevokedStatus(summary.getRevocationTime().toDate(), summary.getRevocationReason().getCode());
//                break;
//            case EXPIRED:
//                status = new RevokedStatus(summary.getExpirationTime().toDate(), SUPERSEDED.getCode());
//                break;
//            case UNKNOWN:
//                status = getUnknownStatus();
//                break;
//            default:
//                throw new IllegalArgumentException("Unknown status! " + summary.getStatus().name());
//        }
//        DateTime updateTime = summary.getThisUpdateTime();
//        return new OCSPCertificateStatusWrapper(status,
//                updateTime,
//                updateTime.plusSeconds(certificateManager.getRefreshSeconds())
//        );
//    }
//
//    /**
//     * Gets the unknown CertificateStatus to return depending on the value of {@code rejectUnknown}
//     *
//     * @return The CertificateStatus to use for unknown certificates
//     */
//    private CertificateStatus getUnknownStatus() {
//        if (rejectUnknown) {
//            return new RevokedStatus(DateTime.now().toDate(), UNSPECIFIED.getCode());
//        } else {
//            return new UnknownStatus();
//        }
//    }
//
//    /**
//     * Builds and signs the response in the builder
//     *
//     * @param responseBuilder The builder
//     * @return The signed response
//     */
//    private OCSPResp buildAndSignResponse(BasicOCSPRespBuilder responseBuilder) throws OCSPException {
//        BasicOCSPResp basicResponse = responseBuilder.build(
//                contentSigner,
//                signingCertificateChain,
//                new Date()
//        );
//        return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basicResponse);
//    }
//}
