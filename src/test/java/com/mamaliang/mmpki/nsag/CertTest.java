package com.mamaliang.mmpki.nsag;

import com.mamaliang.mmpki.cert.service.impl.*;
import com.mamaliang.mmpki.cert.vo.CaIssueCertVO;
import com.mamaliang.mmpki.cert.vo.SelfIssueCertVO;
import com.mamaliang.mmpki.util.X500NameUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.util.Collections;
import java.util.Date;

/**
 * @author gaof
 * @date 2023/12/29
 */
@SpringBootTest
public class CertTest {

    @Autowired
    private RSACSRServiceImpl rsaCSRService;

    @Autowired
    private RSACertServiceImpl rsaCertService;

    @Autowired
    private ECCCSRServiceImpl eccCSRService;

    @Autowired
    private ECCCertServiceImpl eccCertService;

    @Autowired
    private SM2CSRServiceImpl sm2CSRService;

    @Autowired
    private SM2CertServiceImpl sm2CertService;

    @Test
    void sm2() throws IOException {
        SelfIssueCertVO vo = new SelfIssueCertVO();
        X500Name siteDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "admin");
        vo.setSubjectDn(siteDn);
        vo.setCa(false);
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年
        vo.setNotBefore(notBefore);
        vo.setNotAfter(notAfter);
        vo.setSubjectAltNames(Collections.singletonList("admin"));
        String[] materials = sm2CertService.selfIssueSingleCert(vo);

//        try (FileWriter cert = new FileWriter("/Users/mamaliang/Downloads/sm2.pem");
//             FileWriter key = new FileWriter("/Users/mamaliang/Downloads/sm2.key")) {
//            cert.write(materials[0]);
//            key.write(materials[1]);
//        }
    }

    @Test
    void ecc() throws IOException {
        SelfIssueCertVO vo = new SelfIssueCertVO();
        X500Name siteDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "www.site.com");
        vo.setSubjectDn(siteDn);
        vo.setCa(false);
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年
        vo.setNotBefore(notBefore);
        vo.setNotAfter(notAfter);
        vo.setSubjectAltNames(Collections.singletonList("www.site.com"));
        String[] materials = eccCertService.selfIssueSingleCert(vo);

//        try (FileWriter cert = new FileWriter("/Users/mamaliang/Downloads/ecc.pem");
//             FileWriter key = new FileWriter("/Users/mamaliang/Downloads/ecc.key")) {
//            cert.write(materials[0]);
//            key.write(materials[1]);
//        }
    }


    @Test
    void rsa() throws IOException {
        SelfIssueCertVO vo = new SelfIssueCertVO();
        X500Name siteDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "www.site.com");
        vo.setSubjectDn(siteDn);
        vo.setCa(false);
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年
        vo.setNotBefore(notBefore);
        vo.setNotAfter(notAfter);
        vo.setSubjectAltNames(Collections.singletonList("www.site.com"));
        String[] materials = rsaCertService.selfIssueSingleCert(vo);

//        try (FileWriter cert = new FileWriter("/Users/mamaliang/Downloads/rsa.pem");
//             FileWriter key = new FileWriter("/Users/mamaliang/Downloads/rsa.key")) {
//            cert.write(materials[0]);
//            key.write(materials[1]);
//        }
    }

    @Test
    void sm2Envelop() throws IOException {

        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年

        SelfIssueCertVO svo = new SelfIssueCertVO();
        X500Name caDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "SM2ROOTCA");
        svo.setSubjectDn(caDn);
        svo.setCa(false);
        svo.setNotBefore(notBefore);
        svo.setNotAfter(notAfter);
        svo.setSubjectAltNames(Collections.singletonList("SM2ROOTCA"));
        String[] caMaterials = sm2CertService.selfIssueSingleCert(svo);

        String p10 = "-----BEGIN CERTIFICATE REQUEST-----\n" +
                "MIH8MIGiAgEAMB0xCzAJBgNVBAYTAkNOMQ4wDAYDVQQDDAV0ZXN0MjBZMBMGByqG\n" +
                "SM49AgEGCCqBHM9VAYItA0IABBOOuB+oq2hrZzVV7Xv/3wTlvOjh6Zhs8cR45BdY\n" +
                "0b9vkOSnZsjB7J/cu2/kOb1pfp3fnrOCzO4ZkzM4xyJ1y4CgIzAhBgkqhkiG9w0B\n" +
                "CQ4xFDASMBAGA1UdEQQJMAeCBXRlc3QyMAwGCCqBHM9VAYN1BQADRwAwRAIgBWzx\n" +
                "fQQqou5DsB0lscrcfL11b3g+zNrCPdkbribg4LQCIC/Xb77yQ9ie1yMttJUzm8Li\n" +
                "9hRoHkWMQuVMkTqDUQ47\n" +
                "-----END CERTIFICATE REQUEST-----";

        CaIssueCertVO cvo = new CaIssueCertVO();
        cvo.setCa(false);
        cvo.setNotBefore(notBefore);
        cvo.setNotAfter(notAfter);
        cvo.setCsr(p10);
        cvo.setCaCert(caMaterials[0]);
        cvo.setCaPrivateKey(caMaterials[1]);
        String[] materials = sm2CertService.caIssueDoubleCertWithEnvelop(cvo);
//        try (FileWriter sig = new FileWriter("/Users/mamaliang/Downloads/sig.pem");
//             FileWriter enc = new FileWriter("/Users/mamaliang/Downloads/enc.pem");
//             FileWriter envelop = new FileWriter("/Users/mamaliang/Downloads/envelop.key")) {
//            sig.write(materials[0]);
//
//            enc.write(materials[1]);
//
//            envelop.write(materials[2]);
//        }

    }
}
