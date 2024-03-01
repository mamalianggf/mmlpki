package com.mamaliang.mmpki.cert.service.impl;

import com.mamaliang.mmpki.algorithm.ECC;
import com.mamaliang.mmpki.cert.service.CertService;
import com.mamaliang.mmpki.cert.vo.CaIssueCertVO;
import com.mamaliang.mmpki.cert.vo.SelfIssueCertVO;
import com.mamaliang.mmpki.util.CSRUtil;
import com.mamaliang.mmpki.util.CertUtil;
import com.mamaliang.mmpki.util.PemUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * @author gaof
 * @date 2023/11/18
 */
@Service("ECCCertService")
public class ECCCertServiceImpl implements CertService {
    @Override
    public String[] selfIssueSingleCert(SelfIssueCertVO vo) {
        try {
            KeyPair keyPair = ECC.generateKeyPair();
            boolean isCa = vo.isCa();
            X500Name dn = vo.getSubjectDn();
            Date notBefore = vo.getNotBefore();
            Date notAfter = vo.getNotAfter();
            List<String> sans = vo.getSubjectAltNames();
            Certificate cert = CertUtil.selfIssueCert(isCa, true, true, dn, notBefore, notAfter, sans, keyPair, ECC.SIGNATURE_SHA256_WITH_ECDSA);
            String certPem = PemUtil.cert2pem(cert);
            String privateKeyPem = PemUtil.privateKey2pem(keyPair.getPrivate());
            return new String[]{certPem, privateKeyPem};
        } catch (Exception e) {
            throw new RuntimeException("自签发ECC证书失败", e);
        }
    }

    @Override
    public String[] selfIssueDoubleCert(SelfIssueCertVO selfIssueCertVO) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String caIssueSingleCert(CaIssueCertVO vo) {
        try {
            // subject
            boolean isCa = vo.isCa();
            PKCS10CertificationRequest csr = PemUtil.pem2CSR(vo.getCsr());
            PublicKey subjectPublicKey = CSRUtil.extraPublicKey(csr);
            X500Name subjectDn = csr.getSubject();
            Date notBefore = vo.getNotBefore();
            Date notAfter = vo.getNotAfter();
            Extension sans = Optional.ofNullable(csr.getRequestedExtensions()).map(i->i.getExtension(Extension.subjectAlternativeName)).orElse(null);

            // issuer
            Certificate caCert = PemUtil.pem2Cert(vo.getCaCert());
            X500Name issuerDn = caCert.getSubject();
            PrivateKey issuerPrivateKey = PemUtil.pem2privateKey(vo.getCaPrivateKey());

            Certificate cert = CertUtil.caIssueCert(isCa, true, true, subjectDn, subjectPublicKey, notBefore, notAfter, issuerDn, sans, CertUtil.extraPublicKey(caCert), issuerPrivateKey, ECC.SIGNATURE_SHA256_WITH_ECDSA);

            return PemUtil.cert2pem(cert);
        } catch (Exception e) {
            throw new UnsupportedOperationException("自签发ECC证书失败", e);
        }
    }

    @Override
    public String[] caIssueDoubleCert(CaIssueCertVO caIssueCertVO) {
        throw new RuntimeException("not support");
    }

    @Override
    public String[] caIssueDoubleCertWithEnvelop(CaIssueCertVO caIssueCertVO) {
        throw new UnsupportedOperationException();
    }
}
