package com.mamaliang.mmpki.cert.service.impl;

import com.mamaliang.mmpki.algorithm.SM2;
import com.mamaliang.mmpki.cert.service.CertService;
import com.mamaliang.mmpki.cert.vo.CaIssueCertVO;
import com.mamaliang.mmpki.cert.vo.SelfIssueCertVO;
import com.mamaliang.mmpki.util.CSRUtil;
import com.mamaliang.mmpki.util.CertUtil;
import com.mamaliang.mmpki.util.PemUtil;
import com.mamaliang.mmpki.gmt0016.EnvelopedUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
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
@Service("SM2CertService")
public class SM2CertServiceImpl implements CertService {
    @Override
    public String[] selfIssueSingleCert(SelfIssueCertVO vo) {
        try {
            KeyPair keyPair = SM2.generateKeyPair();
            boolean isCa = vo.isCa();
            X500Name dn = vo.generateX500Name();
            Date notBefore = vo.getNotBefore();
            Date notAfter = vo.getNotAfter();
            List<String> sans = vo.getSubjectAltNames();
            Certificate cert = CertUtil.selfIssueCert(isCa, true, true, dn, notBefore, notAfter, sans, keyPair, SM2.SIGNATURE_SM3_WITH_SM2);
            String certPem = PemUtil.cert2pem(cert);
            String privateKeyPem = PemUtil.privateKey2pem(keyPair.getPrivate());
            return new String[]{certPem, privateKeyPem};
        } catch (Exception e) {
            throw new RuntimeException("自签发SM2证书失败", e);
        }
    }

    @Override
    public String[] selfIssueDoubleCert(SelfIssueCertVO vo) {
        try {
            KeyPair sigKeyPair = SM2.generateKeyPair();
            KeyPair encKeyPair = SM2.generateKeyPair();
            boolean isCa = vo.isCa();
            X500Name dn = vo.generateX500Name();
            Date notBefore = vo.getNotBefore();
            Date notAfter = vo.getNotAfter();
            List<String> sans = vo.getSubjectAltNames();
            Certificate sigCert = CertUtil.selfIssueCert(isCa, true, false, dn, notBefore, notAfter, sans, sigKeyPair, SM2.SIGNATURE_SM3_WITH_SM2);
            Certificate encCert = CertUtil.selfIssueCert(isCa, false, true, dn, notBefore, notAfter, sans, encKeyPair, SM2.SIGNATURE_SM3_WITH_SM2);
            String sigCertPem = PemUtil.cert2pem(sigCert);
            String sigPrivateKeyPem = PemUtil.privateKey2pem(sigKeyPair.getPrivate());
            String encCertPem = PemUtil.cert2pem(encCert);
            String encPrivateKeyPem = PemUtil.privateKey2pem(encKeyPair.getPrivate());
            return new String[]{sigCertPem, sigPrivateKeyPem, encCertPem, encPrivateKeyPem};
        } catch (Exception e) {
            throw new RuntimeException("自签发SM2证书失败", e);
        }
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
            Extension sans = Optional.ofNullable(csr.getRequestedExtensions()).map(i -> i.getExtension(Extension.subjectAlternativeName)).orElse(null);


            // issuer
            Certificate caCert = PemUtil.pem2Cert(vo.getCaCert());
            X500Name issuerDn = caCert.getSubject();
            PrivateKey issuerPrivateKey = PemUtil.pem2privateKey(vo.getCaPrivateKey());

            Certificate cert = CertUtil.caIssueCert(isCa, true, true, subjectDn, subjectPublicKey, notBefore, notAfter, issuerDn, sans, CertUtil.extraPublicKey(caCert), issuerPrivateKey, SM2.SIGNATURE_SM3_WITH_SM2);

            return PemUtil.cert2pem(cert);
        } catch (Exception e) {
            throw new RuntimeException("自签发SM2证书失败", e);
        }
    }

    @Override
    public String[] caIssueDoubleCert(CaIssueCertVO vo) {
        try {
            // subject
            KeyPair encKeyPair = SM2.generateKeyPair();
            boolean isCa = vo.isCa();
            PKCS10CertificationRequest csr = PemUtil.pem2CSR(vo.getCsr());
            PublicKey sigSubjectPublicKey = CSRUtil.extraPublicKey(csr);
            X500Name subjectDn = csr.getSubject();
            Date notBefore = vo.getNotBefore();
            Date notAfter = vo.getNotAfter();
            Extension sans = Optional.ofNullable(csr.getRequestedExtensions()).map(i -> i.getExtension(Extension.subjectAlternativeName)).orElse(null);

            // issuer
            Certificate caCert = PemUtil.pem2Cert(vo.getCaCert());
            X500Name issuerDn = caCert.getSubject();
            PrivateKey issuerPrivateKey = PemUtil.pem2privateKey(vo.getCaPrivateKey());

            Certificate sigCert = CertUtil.caIssueCert(isCa, true, false, subjectDn, sigSubjectPublicKey, notBefore, notAfter, issuerDn, sans, CertUtil.extraPublicKey(caCert), issuerPrivateKey, SM2.SIGNATURE_SM3_WITH_SM2);
            Certificate encCert = CertUtil.caIssueCert(isCa, false, true, subjectDn, encKeyPair.getPublic(), notBefore, notAfter, issuerDn, sans, CertUtil.extraPublicKey(caCert), issuerPrivateKey, SM2.SIGNATURE_SM3_WITH_SM2);

            String sigCertPem = PemUtil.cert2pem(sigCert);
            String encCertPem = PemUtil.cert2pem(encCert);
            String encPrivateKeyPem = PemUtil.privateKey2pem(encKeyPair.getPrivate());
            return new String[]{sigCertPem, encCertPem, encPrivateKeyPem};
        } catch (Exception e) {
            throw new RuntimeException("自签发SM2证书失败", e);
        }
    }

    @Override
    public String[] caIssueDoubleCertWithEnvelop(CaIssueCertVO vo) {
        try {
            // subject
            KeyPair encKeyPair = SM2.generateKeyPair();
            boolean isCa = vo.isCa();
            PKCS10CertificationRequest csr = PemUtil.pem2CSR(vo.getCsr());
            PublicKey sigSubjectPublicKey = CSRUtil.extraPublicKey(csr);
            X500Name subjectDn = csr.getSubject();
            Date notBefore = vo.getNotBefore();
            Date notAfter = vo.getNotAfter();
            Extension sans = Optional.ofNullable(csr.getRequestedExtensions()).map(i -> i.getExtension(Extension.subjectAlternativeName)).orElse(null);

            // issuer
            Certificate caCert = PemUtil.pem2Cert(vo.getCaCert());
            X500Name issuerDn = caCert.getSubject();
            PrivateKey issuerPrivateKey = PemUtil.pem2privateKey(vo.getCaPrivateKey());

            Certificate sigCert = CertUtil.caIssueCert(isCa, true, false, subjectDn, sigSubjectPublicKey, notBefore, notAfter, issuerDn, sans, CertUtil.extraPublicKey(caCert), issuerPrivateKey, SM2.SIGNATURE_SM3_WITH_SM2);
            Certificate encCert = CertUtil.caIssueCert(isCa, false, true, subjectDn, encKeyPair.getPublic(), notBefore, notAfter, issuerDn, sans, CertUtil.extraPublicKey(caCert), issuerPrivateKey, SM2.SIGNATURE_SM3_WITH_SM2);

            String sigCertPem = PemUtil.cert2pem(sigCert);
            String encCertPem = PemUtil.cert2pem(encCert);

            String envelop = EnvelopedUtil.assemble((BCECPrivateKey) encKeyPair.getPrivate(), (BCECPublicKey) encKeyPair.getPublic(), (BCECPublicKey) sigSubjectPublicKey);
            return new String[]{sigCertPem, encCertPem, envelop};
        } catch (Exception e) {
            throw new RuntimeException("自签发SM2密钥不落地证书失败", e);
        }
    }
}
