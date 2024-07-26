package com.mamaliang.mmpki.cert.service;

import com.mamaliang.mmpki.algorithm.SM2;
import com.mamaliang.mmpki.cert.model.*;
import com.mamaliang.mmpki.gmt0016.EnvelopedUtil;
import com.mamaliang.mmpki.util.CSRUtil;
import com.mamaliang.mmpki.util.CertUtil;
import com.mamaliang.mmpki.util.PemUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.*;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * @author gaof
 * @date 2024/7/4
 */
public abstract class AbstractCertService {

    public CsrWithPrivateKey generateCsr(CsrVO csrVO) {
        try {
            KeyPair keyPair = generateKeyPair();
            String signatureAlgorithm = signatureAlgorithm();
            PKCS10CertificationRequest p10 = CSRUtil.generateCSR(csrVO.getSubjectDn(), csrVO.getSubjectAltNames(), keyPair, signatureAlgorithm);
            String csrPem = PemUtil.csr2pem(p10);
            String privateKeyPem = PemUtil.privateKey2pem(keyPair.getPrivate());
            return new CsrWithPrivateKey(csrPem, privateKeyPem);
        } catch (Exception e) {
            throw new RuntimeException("签发证书请求失败", e);
        }

    }

    public CertWithPrivateKey selfIssueSingleCert(SelfIssueCertVO vo) {
        try {
            KeyPair keyPair = generateKeyPair();
            boolean isCa = vo.isCa();
            X500Name dn = vo.getSubjectDn();
            Date notBefore = vo.getNotBefore();
            Date notAfter = vo.getNotAfter();
            List<String> sans = vo.getSubjectAltNames();
            String signatureAlgorithm = signatureAlgorithm();
            Certificate cert = CertUtil.selfIssueCert(isCa, true, true, dn, notBefore, notAfter, sans, keyPair, signatureAlgorithm);
            String certPem = PemUtil.cert2pem(cert);
            String privateKeyPem = PemUtil.privateKey2pem(keyPair.getPrivate());
            return new CertWithPrivateKey(certPem, privateKeyPem);
        } catch (Exception e) {
            throw new RuntimeException("自签发单证书失败", e);
        }

    }

    public DoubleCertWithDoublePrivateKey selfIssueDoubleCert(SelfIssueCertVO vo) {
        try {
            KeyPair sigKeyPair = generateKeyPair();
            KeyPair encKeyPair = generateKeyPair();
            boolean isCa = vo.isCa();
            X500Name dn = vo.getSubjectDn();
            Date notBefore = vo.getNotBefore();
            Date notAfter = vo.getNotAfter();
            List<String> sans = vo.getSubjectAltNames();
            String signatureAlgorithm = signatureAlgorithm();
            Certificate sigCert = CertUtil.selfIssueCert(isCa, true, false, dn, notBefore, notAfter, sans, sigKeyPair, signatureAlgorithm);
            Certificate encCert = CertUtil.selfIssueCert(isCa, false, true, dn, notBefore, notAfter, sans, encKeyPair, signatureAlgorithm);
            String sigCertPem = PemUtil.cert2pem(sigCert);
            String sigPrivateKeyPem = PemUtil.privateKey2pem(sigKeyPair.getPrivate());
            String encCertPem = PemUtil.cert2pem(encCert);
            String encPrivateKeyPem = PemUtil.privateKey2pem(encKeyPair.getPrivate());
            CertWithPrivateKey sig = new CertWithPrivateKey(sigCertPem, sigPrivateKeyPem);
            CertWithPrivateKey enc = new CertWithPrivateKey(encCertPem, encPrivateKeyPem);
            return new DoubleCertWithDoublePrivateKey(sig, enc);
        } catch (Exception e) {
            throw new RuntimeException("自签发双证书失败", e);
        }
    }

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

            String signatureAlgorithm = signatureAlgorithm();
            Certificate cert = CertUtil.caIssueCert(isCa, true, true, subjectDn, subjectPublicKey, notBefore, notAfter, issuerDn, sans, CertUtil.extraPublicKey(caCert), issuerPrivateKey, signatureAlgorithm);

            return PemUtil.cert2pem(cert);
        } catch (Exception e) {
            throw new RuntimeException("ca签发单证书失败", e);
        }
    }


    public DoubleCertWithPrivateKey caIssueDoubleCert(CaIssueCertVO vo) {
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

            String signatureAlgorithm = signatureAlgorithm();
            Certificate sigCert = CertUtil.caIssueCert(isCa, true, false, subjectDn, sigSubjectPublicKey, notBefore, notAfter, issuerDn, sans, CertUtil.extraPublicKey(caCert), issuerPrivateKey, signatureAlgorithm);
            Certificate encCert = CertUtil.caIssueCert(isCa, false, true, subjectDn, encKeyPair.getPublic(), notBefore, notAfter, issuerDn, sans, CertUtil.extraPublicKey(caCert), issuerPrivateKey, signatureAlgorithm);

            String sigCertPem = PemUtil.cert2pem(sigCert);
            String encCertPem = PemUtil.cert2pem(encCert);
            String encPrivateKeyPem = PemUtil.privateKey2pem(encKeyPair.getPrivate());
            return new DoubleCertWithPrivateKey(sigCertPem, encCertPem, encPrivateKeyPem);
        } catch (Exception e) {
            throw new RuntimeException("ca签发双证书失败", e);
        }
    }

    public DoubleCertWithEnvelop caIssueDoubleCertWithEnvelop(CaIssueCertVO vo) {
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

            String signatureAlgorithm = signatureAlgorithm();
            Certificate sigCert = CertUtil.caIssueCert(isCa, true, false, subjectDn, sigSubjectPublicKey, notBefore, notAfter, issuerDn, sans, CertUtil.extraPublicKey(caCert), issuerPrivateKey, signatureAlgorithm);
            Certificate encCert = CertUtil.caIssueCert(isCa, false, true, subjectDn, encKeyPair.getPublic(), notBefore, notAfter, issuerDn, sans, CertUtil.extraPublicKey(caCert), issuerPrivateKey, signatureAlgorithm);

            String sigCertPem = PemUtil.cert2pem(sigCert);
            String encCertPem = PemUtil.cert2pem(encCert);

            String envelop = EnvelopedUtil.assembleFront((BCECPrivateKey) encKeyPair.getPrivate(), (BCECPublicKey) encKeyPair.getPublic(), (BCECPublicKey) sigSubjectPublicKey);
            return new DoubleCertWithEnvelop(sigCertPem, encCertPem, envelop);
        } catch (Exception e) {
            throw new RuntimeException("ca签发密钥不落地证书失败", e);
        }
    }

    public abstract KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException;

    public abstract String signatureAlgorithm();

}
