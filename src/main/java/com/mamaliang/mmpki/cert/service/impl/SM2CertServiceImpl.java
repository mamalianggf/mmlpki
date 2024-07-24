package com.mamaliang.mmpki.cert.service.impl;

import com.mamaliang.mmpki.algorithm.SM2;
import com.mamaliang.mmpki.cert.service.AbstractCertService;
import org.springframework.stereotype.Service;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

/**
 * @author gaof
 * @date 2023/11/17
 */
public class SM2CertServiceImpl extends AbstractCertService {
    @Override
    public KeyPair generateKeyPair() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        return SM2.generateKeyPair();
    }

    @Override
    public String signatureAlgorithm() {
        return SM2.SIGNATURE_SM3_WITH_SM2;
    }
}
