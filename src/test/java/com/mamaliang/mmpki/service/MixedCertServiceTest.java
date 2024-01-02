package com.mamaliang.mmpki.service;

import com.mamaliang.mmpki.cert.service.impl.RSACSRServiceImpl;
import com.mamaliang.mmpki.cert.service.impl.RSACertServiceImpl;
import com.mamaliang.mmpki.cert.service.impl.SM2CSRServiceImpl;
import com.mamaliang.mmpki.cert.service.impl.SM2CertServiceImpl;
import com.mamaliang.mmpki.cert.vo.CSRVO;
import com.mamaliang.mmpki.cert.vo.CaIssueCertVO;
import com.mamaliang.mmpki.cert.vo.SelfIssueCertVO;
import com.mamaliang.mmpki.util.PemUtil;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * @author gaof
 * @date 2023/10/31
 */
@SpringBootTest
public class MixedCertServiceTest {

    @Autowired
    private RSACSRServiceImpl rsaCSRService;

    @Autowired
    private RSACertServiceImpl rsaCertService;

    @Autowired
    private SM2CSRServiceImpl sm2CSRService;

    @Autowired
    private SM2CertServiceImpl sm2CertService;

    @Test
    void testRSACaIssueSM2Certificate() throws NoSuchAlgorithmException, OperatorCreationException, IOException, InvalidAlgorithmParameterException {

        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年

        SelfIssueCertVO svo = new SelfIssueCertVO();
        svo.setCountry("CN");
        svo.setStateOrProvince("SH");
        svo.setLocality("SH");
        svo.setOrganization("FUTURE");
        svo.setOrganizationUnit("FUTURE");
        svo.setCommonName("RSAROOTCA");
        svo.setCa(false);
        svo.setNotBefore(notBefore);
        svo.setNotAfter(notAfter);
        svo.setSubjectAltNames(Collections.singletonList("RSAROOTCA"));
        String[] caMaterials = rsaCertService.selfIssueSingleCert(svo);

        CSRVO csrvo = new CSRVO();
        csrvo.setCountry("CN");
        csrvo.setStateOrProvince("SH");
        csrvo.setLocality("SH");
        csrvo.setOrganization("FUTURE");
        csrvo.setOrganizationUnit("FUTURE");
        csrvo.setCommonName("www.site.com");
        List<String> sans = Collections.singletonList("www.site.com");
        csrvo.setSubjectAltNames(sans);
        String[] csrMaterials = sm2CSRService.generateCSR(csrvo);


        CaIssueCertVO cvo = new CaIssueCertVO();
        cvo.setCa(false);
        cvo.setNotBefore(notBefore);
        cvo.setNotAfter(notAfter);
        cvo.setCsr(csrMaterials[0]);
        cvo.setCaCert(caMaterials[0]);
        cvo.setCaPrivateKey(caMaterials[1]);
        String materials = rsaCertService.caIssueSingleCert(cvo);

        Certificate certificate = PemUtil.pem2Cert(materials);
        RDN[] rdNs = certificate.getSubject().getRDNs(BCStyle.CN);
        Assertions.assertEquals("www.site.com", rdNs[0].getTypesAndValues()[0].getValue().toString());

    }

    @Test
    void testSM2CaIssueRSACertificate() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, OperatorCreationException, IOException {
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年

        SelfIssueCertVO svo = new SelfIssueCertVO();
        svo.setCountry("CN");
        svo.setStateOrProvince("SH");
        svo.setLocality("SH");
        svo.setOrganization("FUTURE");
        svo.setOrganizationUnit("FUTURE");
        svo.setCommonName("SM2ROOTCA");
        svo.setCa(false);
        svo.setNotBefore(notBefore);
        svo.setNotAfter(notAfter);
        svo.setSubjectAltNames(Collections.singletonList("SM2ROOTCA"));
        String[] caMaterials = sm2CertService.selfIssueSingleCert(svo);

        CSRVO csrvo = new CSRVO();
        csrvo.setCountry("CN");
        csrvo.setStateOrProvince("SH");
        csrvo.setLocality("SH");
        csrvo.setOrganization("FUTURE");
        csrvo.setOrganizationUnit("FUTURE");
        csrvo.setCommonName("www.site.com");
        List<String> sans = Collections.singletonList("www.site.com");
        csrvo.setSubjectAltNames(sans);
        String[] csrMaterials = rsaCSRService.generateCSR(csrvo);

        CaIssueCertVO cvo = new CaIssueCertVO();
        cvo.setCa(false);
        cvo.setNotBefore(notBefore);
        cvo.setNotAfter(notAfter);
        cvo.setCsr(csrMaterials[0]);
        cvo.setCaCert(caMaterials[0]);
        cvo.setCaPrivateKey(caMaterials[1]);
        String materials = sm2CertService.caIssueSingleCert(cvo);

        Certificate certificate = PemUtil.pem2Cert(materials);
        RDN[] rdNs = certificate.getSubject().getRDNs(BCStyle.CN);
        Assertions.assertEquals("www.site.com", rdNs[0].getTypesAndValues()[0].getValue().toString());
    }
}
