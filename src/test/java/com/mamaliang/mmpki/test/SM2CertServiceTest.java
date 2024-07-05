package com.mamaliang.mmpki.test;

import com.mamaliang.mmpki.cert.model.*;
import com.mamaliang.mmpki.cert.service.impl.SM2CertServiceImpl;
import com.mamaliang.mmpki.util.PemUtil;
import com.mamaliang.mmpki.util.X500NameUtil;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Certificate;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * @author gaof
 * @date 2023/10/30
 */
@SpringBootTest
public class SM2CertServiceTest {

    @Autowired
    private SM2CertServiceImpl sm2CertService;

    @Test
    void testSelfIssueSiteCertificate() throws IOException {
        SelfIssueCertVO vo = new SelfIssueCertVO();
        X500Name siteDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "www.site.com");
        vo.setSubjectDn(siteDn);
        vo.setCa(false);
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年
        vo.setNotBefore(notBefore);
        vo.setNotAfter(notAfter);
        vo.setSubjectAltNames(Collections.singletonList("www.site.com"));
        CertWithPrivateKey certWithPrivateKey = sm2CertService.selfIssueSingleCert(vo);
        Certificate certificate = PemUtil.pem2Cert(certWithPrivateKey.cert());
        RDN[] rdNs = certificate.getSubject().getRDNs(BCStyle.CN);
        Assertions.assertEquals("www.site.com", rdNs[0].getTypesAndValues()[0].getValue().toString());
    }

    @Test
    void testSelfIssueDoubleSiteCertificate() throws IOException {
        SelfIssueCertVO vo = new SelfIssueCertVO();
        X500Name siteDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "www.site.com");
        vo.setSubjectDn(siteDn);
        vo.setCa(false);
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年
        vo.setNotBefore(notBefore);
        vo.setNotAfter(notAfter);
        vo.setSubjectAltNames(Collections.singletonList("www.site.com"));
        DoubleCertWithDoublePrivateKey doubleCertWithDoublePrivateKey = sm2CertService.selfIssueDoubleCert(vo);
        Certificate sigCert = PemUtil.pem2Cert(doubleCertWithDoublePrivateKey.sigCert());
        RDN[] sigRdNs = sigCert.getSubject().getRDNs(BCStyle.CN);
        Assertions.assertEquals("www.site.com", sigRdNs[0].getTypesAndValues()[0].getValue().toString());
        Certificate encCert = PemUtil.pem2Cert(doubleCertWithDoublePrivateKey.encCert());
        RDN[] encRdNs = encCert.getSubject().getRDNs(BCStyle.CN);
        Assertions.assertEquals("www.site.com", encRdNs[0].getTypesAndValues()[0].getValue().toString());
    }

    @Test
    void testCaIssueSiteCertificate() throws IOException {

        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年

        SelfIssueCertVO svo = new SelfIssueCertVO();
        X500Name caDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "SM2ROOTCA");
        svo.setSubjectDn(caDn);
        svo.setCa(false);
        svo.setNotBefore(notBefore);
        svo.setNotAfter(notAfter);
        svo.setSubjectAltNames(Collections.singletonList("SM2ROOTCA"));
        CertWithPrivateKey caCertWithPrivateKey = sm2CertService.selfIssueSingleCert(svo);

        CsrVO csrvo = new CsrVO();
        X500Name siteDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "www.site.com");
        csrvo.setSubjectDn(siteDn);
        List<String> sans = Collections.singletonList("www.site.com");
        csrvo.setSubjectAltNames(sans);
        CsrWithPrivateKey csrWithPrivateKey = sm2CertService.generateCsr(csrvo);

        CaIssueCertVO cvo = new CaIssueCertVO();
        cvo.setCa(false);
        cvo.setNotBefore(notBefore);
        cvo.setNotAfter(notAfter);
        cvo.setCsr(csrWithPrivateKey.csr());
        cvo.setCaCert(caCertWithPrivateKey.cert());
        cvo.setCaPrivateKey(caCertWithPrivateKey.privateKey());
        String cert = sm2CertService.caIssueSingleCert(cvo);

        Certificate certificate = PemUtil.pem2Cert(cert);
        RDN[] rdNs = certificate.getSubject().getRDNs(BCStyle.CN);
        Assertions.assertEquals("www.site.com", rdNs[0].getTypesAndValues()[0].getValue().toString());
    }


    @Test
    void testCaIssueDoubleSiteCertificate() throws IOException {

        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年

        SelfIssueCertVO svo = new SelfIssueCertVO();
        X500Name caDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "SM2ROOTCA");
        svo.setSubjectDn(caDn);
        svo.setCa(false);
        svo.setNotBefore(notBefore);
        svo.setNotAfter(notAfter);
        svo.setSubjectAltNames(Collections.singletonList("SM2ROOTCA"));
        CertWithPrivateKey caCertWithPrivateKey = sm2CertService.selfIssueSingleCert(svo);

        CsrVO csrvo = new CsrVO();
        X500Name siteDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "www.site.com");
        csrvo.setSubjectDn(siteDn);
        List<String> sans = Collections.singletonList("www.site.com");
        csrvo.setSubjectAltNames(sans);
        CsrWithPrivateKey csrWithPrivateKey = sm2CertService.generateCsr(csrvo);


        CaIssueCertVO cvo = new CaIssueCertVO();
        cvo.setCa(false);
        cvo.setNotBefore(notBefore);
        cvo.setNotAfter(notAfter);
        cvo.setCsr(csrWithPrivateKey.csr());
        cvo.setCaCert(caCertWithPrivateKey.cert());
        cvo.setCaPrivateKey(caCertWithPrivateKey.privateKey());
        DoubleCertWithPrivateKey doubleCertWithPrivateKey = sm2CertService.caIssueDoubleCert(cvo);

        Certificate sigCert = PemUtil.pem2Cert(doubleCertWithPrivateKey.sigCert());
        RDN[] sigRdNs = sigCert.getSubject().getRDNs(BCStyle.CN);
        Assertions.assertEquals("www.site.com", sigRdNs[0].getTypesAndValues()[0].getValue().toString());
        Certificate encCert = PemUtil.pem2Cert(doubleCertWithPrivateKey.encCert());
        RDN[] encRdNs = encCert.getSubject().getRDNs(BCStyle.CN);
        Assertions.assertEquals("www.site.com", encRdNs[0].getTypesAndValues()[0].getValue().toString());


    }

    @Test
    void testCaIssueDoubleCertWithEnvelop() throws Exception {

        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年

        SelfIssueCertVO svo = new SelfIssueCertVO();
        X500Name caDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "SM2ROOTCA");
        svo.setSubjectDn(caDn);
        svo.setCa(false);
        svo.setNotBefore(notBefore);
        svo.setNotAfter(notAfter);
        svo.setSubjectAltNames(Collections.singletonList("SM2ROOTCA"));
        CertWithPrivateKey caCertWithPrivateKey = sm2CertService.selfIssueSingleCert(svo);

        CsrVO csrvo = new CsrVO();
        X500Name siteDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "www.site.com");
        csrvo.setSubjectDn(siteDn);
        List<String> sans = Collections.singletonList("www.site.com");
        csrvo.setSubjectAltNames(sans);
        CsrWithPrivateKey csrWithPrivateKey = sm2CertService.generateCsr(csrvo);

        CaIssueCertVO cvo = new CaIssueCertVO();
        cvo.setCa(false);
        cvo.setNotBefore(notBefore);
        cvo.setNotAfter(notAfter);
        cvo.setCsr(csrWithPrivateKey.csr());
        cvo.setCaCert(caCertWithPrivateKey.cert());
        cvo.setCaPrivateKey(caCertWithPrivateKey.privateKey());
        DoubleCertWithEnvelop doubleCertWithEnvelop = sm2CertService.caIssueDoubleCertWithEnvelop(cvo);

        Certificate sigCert = PemUtil.pem2Cert(doubleCertWithEnvelop.sigCert());
        RDN[] sigRdNs = sigCert.getSubject().getRDNs(BCStyle.CN);
        Assertions.assertEquals("www.site.com", sigRdNs[0].getTypesAndValues()[0].getValue().toString());
        Certificate encCert = PemUtil.pem2Cert(doubleCertWithEnvelop.encCert());
        RDN[] encRdNs = encCert.getSubject().getRDNs(BCStyle.CN);
        Assertions.assertEquals("www.site.com", encRdNs[0].getTypesAndValues()[0].getValue().toString());
    }


}
