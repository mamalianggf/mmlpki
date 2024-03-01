package com.mamaliang.mmpki.cert.service.impl;

import com.mamaliang.mmpki.algorithm.SM2;
import com.mamaliang.mmpki.cert.service.CSRService;
import com.mamaliang.mmpki.cert.vo.CSRVO;
import com.mamaliang.mmpki.util.CSRUtil;
import com.mamaliang.mmpki.util.PemUtil;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.stereotype.Service;

import java.security.KeyPair;

/**
 * @author gaof
 * @date 2023/11/17
 */
@Service("SM2CSRService")
public class SM2CSRServiceImpl implements CSRService {

    @Override
    public String[] generateCSR(CSRVO vo) {
        try {
            KeyPair keyPair = SM2.generateKeyPair();
            PKCS10CertificationRequest p10 = CSRUtil.generateCSR(vo.getSubjectDn(), vo.getSubjectAltNames(), keyPair, SM2.SIGNATURE_SM3_WITH_SM2);
            String csrPem = PemUtil.csr2pem(p10);
            String privateKeyPem = PemUtil.privateKey2pem(keyPair.getPrivate());
            return new String[]{csrPem, privateKeyPem};
        } catch (Exception e) {
            throw new RuntimeException("生成SM2证书请求失败", e);
        }
    }
}
