package com.mamaliang.mmpki.service;

import com.mamaliang.mmpki.cert.service.CSRService;
import com.mamaliang.mmpki.cert.service.CertService;
import com.mamaliang.mmpki.cert.vo.CSRVO;
import com.mamaliang.mmpki.cert.vo.CaIssueCertVO;
import com.mamaliang.mmpki.cert.vo.SelfIssueCertVO;
import com.mamaliang.mmpki.util.PemUtil;
import org.bouncycastle.asn1.x500.RDN;
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
        vo.setCountry("CN");
        vo.setStateOrProvince("SH");
        vo.setLocality("SH");
        vo.setOrganization("FUTURE");
        vo.setOrganizationUnit("FUTURE");
        vo.setCommonName("www.site.com");
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
        svo.setCountry("CN");
        svo.setStateOrProvince("SH");
        svo.setLocality("SH");
        svo.setOrganization("FUTURE");
        svo.setOrganizationUnit("FUTURE");
        svo.setCommonName("ECCROOTCA");
        svo.setCa(false);
        svo.setNotBefore(notBefore);
        svo.setNotAfter(notAfter);
        svo.setSubjectAltNames(Collections.singletonList("ECCROOTCA"));
        String[] caMaterials = certService.selfIssueSingleCert(svo);


        CSRVO csrvo = new CSRVO();
        csrvo.setCountry("CN");
        csrvo.setStateOrProvince("SH");
        csrvo.setLocality("SH");
        csrvo.setOrganization("FUTURE");
        csrvo.setOrganizationUnit("FUTURE");
        csrvo.setCommonName("www.site.com");
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
