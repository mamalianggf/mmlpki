package com.mamaliang.mmpki.cert.service.impl;

import com.mamaliang.mmpki.algorithm.RSA;
import com.mamaliang.mmpki.cert.model.*;
import com.mamaliang.mmpki.cert.service.AbstractCertService;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

/**
 * @author gaof
 * @date 2023/11/17
 */
public class RSACertServiceImpl extends AbstractCertService {

    @Override
    public KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        return RSA.generateKeyPair(RSA.DEFAULT_KEY_SIZE);
    }

    @Override
    public String signatureAlgorithm() {
        return RSA.SIGNATURE_SHA256_WITH_RSA;
    }

    @Override
    public DoubleCertWithDoublePrivateKey selfIssueDoubleCert(SelfIssueCertVO vo) {
        throw new UnsupportedOperationException();
    }

    @Override
    public DoubleCertWithPrivateKey caIssueDoubleCert(CaIssueCertVO vo) {
        throw new UnsupportedOperationException();
    }

    @Override
    public DoubleCertWithEnvelop caIssueDoubleCertWithEnvelop(CaIssueCertVO vo) {
        throw new UnsupportedOperationException();
    }
}
