package com.mamaliang.mmpki.cert.service.impl;

import com.mamaliang.mmpki.algorithm.RSA;
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
@Service("RSACSRService")
public class RSACSRServiceImpl implements CSRService {

    @Override
    public String[] generateCSR(CSRVO vo) {
        try {
            KeyPair keyPair = RSA.generateKeyPair(RSA.DEFAULT_KEY_SIZE);
            PKCS10CertificationRequest p10 = CSRUtil.generateCSR(vo.generateX500Name(), vo.getSubjectAltNames(), keyPair, RSA.SIGNATURE_SHA256_WITH_RSA);
            String csrPem = PemUtil.csr2pem(p10);
            String privateKeyPem = PemUtil.privateKey2pem(keyPair.getPrivate());
            return new String[]{csrPem, privateKeyPem};
        } catch (Exception e) {
            throw new RuntimeException("生成RSA证书请求失败", e);
        }
    }
}
