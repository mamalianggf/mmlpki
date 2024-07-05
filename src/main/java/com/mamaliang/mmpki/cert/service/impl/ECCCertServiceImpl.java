package com.mamaliang.mmpki.cert.service.impl;

import com.mamaliang.mmpki.algorithm.ECC;
import com.mamaliang.mmpki.cert.model.DoubleCertWithDoublePrivateKey;
import com.mamaliang.mmpki.cert.model.DoubleCertWithEnvelop;
import com.mamaliang.mmpki.cert.model.DoubleCertWithPrivateKey;
import com.mamaliang.mmpki.cert.service.AbstractCertService;
import com.mamaliang.mmpki.cert.model.CaIssueCertVO;
import com.mamaliang.mmpki.cert.model.SelfIssueCertVO;
import org.springframework.stereotype.Service;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

/**
 * @author gaof
 * @date 2023/11/17
 */
@Service("ECCCertService")
public class ECCCertServiceImpl extends AbstractCertService {

    @Override
    public KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        return ECC.generateKeyPair();
    }

    @Override
    public String signatureAlgorithm() {
        return ECC.SIGNATURE_SHA256_WITH_ECDSA;
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
