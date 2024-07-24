package com.mamaliang.mmpki.test;

import com.mamaliang.mmpki.cert.model.*;
import com.mamaliang.mmpki.cert.service.impl.ECCCertServiceImpl;
import com.mamaliang.mmpki.util.PemUtil;
import com.mamaliang.mmpki.util.X500NameUtil;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Certificate;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.List;


class ECCCertServiceTest {



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
        CertWithPrivateKey certWithPrivateKey = new ECCCertServiceImpl().selfIssueSingleCert(vo);
        Certificate certificate = PemUtil.pem2Cert(certWithPrivateKey.cert());
        RDN[] rdNs = certificate.getSubject().getRDNs(BCStyle.CN);
        Assertions.assertEquals("www.site.com", rdNs[0].getTypesAndValues()[0].getValue().toString());
    }

    @Test
    void testCaIssueSiteCertificate() throws IOException {

        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年

        SelfIssueCertVO svo = new SelfIssueCertVO();
        svo.setCa(false);
        svo.setNotBefore(notBefore);
        svo.setNotAfter(notAfter);
        X500Name caDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "ECCROOTCA");
        svo.setSubjectDn(caDn);
        svo.setSubjectAltNames(Collections.singletonList("ECCROOTCA"));
        CertWithPrivateKey caCertWithPrivateKey = new ECCCertServiceImpl().selfIssueSingleCert(svo);


        CsrVO csrvo = new CsrVO();
        X500Name siteDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "www.site.com");
        csrvo.setSubjectDn(siteDn);
        List<String> sans = Collections.singletonList("www.site.com");
        csrvo.setSubjectAltNames(sans);
        CsrWithPrivateKey csrWithPrivateKey = new ECCCertServiceImpl().generateCsr(csrvo);


        CaIssueCertVO cvo = new CaIssueCertVO();
        cvo.setCa(false);
        cvo.setNotBefore(notBefore);
        cvo.setNotAfter(notAfter);
        cvo.setCsr(csrWithPrivateKey.csr());
        cvo.setCaCert(caCertWithPrivateKey.cert());
        cvo.setCaPrivateKey(caCertWithPrivateKey.privateKey());
        String cert = new ECCCertServiceImpl().caIssueSingleCert(cvo);

        Certificate certificate = PemUtil.pem2Cert(cert);
        RDN[] rdNs = certificate.getSubject().getRDNs(BCStyle.CN);
        Assertions.assertEquals("www.site.com", rdNs[0].getTypesAndValues()[0].getValue().toString());
    }
}
