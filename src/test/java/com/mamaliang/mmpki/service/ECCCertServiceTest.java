package com.mamaliang.mmpki.service;

import com.mamaliang.mmpki.cert.service.CSRService;
import com.mamaliang.mmpki.cert.service.CertService;
import com.mamaliang.mmpki.cert.vo.CSRVO;
import com.mamaliang.mmpki.cert.vo.CaIssueCertVO;
import com.mamaliang.mmpki.cert.vo.SelfIssueCertVO;
import com.mamaliang.mmpki.util.PemUtil;
import com.mamaliang.mmpki.util.X500NameUtil;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Certificate;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.List;


@SpringBootTest
class ECCCertServiceTest {

    @Qualifier("ECCCertService")
    @Autowired
    private CertService certService;

    @Qualifier("ECCCSRService")
    @Autowired
    private CSRService csrService;

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
        String[] materials = certService.selfIssueSingleCert(vo);
        Certificate certificate = PemUtil.pem2Cert(materials[0]);
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
        String[] caMaterials = certService.selfIssueSingleCert(svo);


        CSRVO csrvo = new CSRVO();
        X500Name siteDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "www.site.com");
        csrvo.setSubjectDn(siteDn);
        List<String> sans = Collections.singletonList("www.site.com");
        csrvo.setSubjectAltNames(sans);
        String[] csrMaterials = csrService.generateCSR(csrvo);


        CaIssueCertVO cvo = new CaIssueCertVO();
        cvo.setCa(false);
        cvo.setNotBefore(notBefore);
        cvo.setNotAfter(notAfter);
        cvo.setCsr(csrMaterials[0]);
        cvo.setCaCert(caMaterials[0]);
        cvo.setCaPrivateKey(caMaterials[1]);
        String materials = certService.caIssueSingleCert(cvo);

        Certificate certificate = PemUtil.pem2Cert(materials);
        RDN[] rdNs = certificate.getSubject().getRDNs(BCStyle.CN);
        Assertions.assertEquals("www.site.com", rdNs[0].getTypesAndValues()[0].getValue().toString());
    }
}
