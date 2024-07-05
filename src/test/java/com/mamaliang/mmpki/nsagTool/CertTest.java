package com.mamaliang.mmpki.nsagTool;

import com.mamaliang.mmpki.cert.model.*;
import com.mamaliang.mmpki.cert.service.AbstractCertService;
import com.mamaliang.mmpki.cert.service.impl.ECCCertServiceImpl;
import com.mamaliang.mmpki.cert.service.impl.RSACertServiceImpl;
import com.mamaliang.mmpki.cert.service.impl.SM2CertServiceImpl;
import com.mamaliang.mmpki.util.X500NameUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.FileWriter;
import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * @author gaof
 * @date 2023/12/29
 */
@Disabled
@SpringBootTest
public class CertTest {

    private final String storePath = "/Users/mamaliang/Workspace/mmlpki/db/";

    @Autowired
    private RSACertServiceImpl rsaCertService;

    @Autowired
    private ECCCertServiceImpl eccCertService;

    @Autowired
    private SM2CertServiceImpl sm2CertService;

    /**
     * sm2 自签单证书
     * ca false
     * 签名+加密
     * key 没密码
     */
    @Test
    void sm2SelfIssueSingleCert() throws IOException {
        String commonName = "www.site.com";

        SelfIssueCertVO vo = new SelfIssueCertVO();
        X500Name siteDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", commonName);
        vo.setSubjectDn(siteDn);
        vo.setCa(false);
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年
        vo.setNotBefore(notBefore);
        vo.setNotAfter(notAfter);
        vo.setSubjectAltNames(Collections.singletonList(commonName));
        CertWithPrivateKey certWithPrivateKey = sm2CertService.selfIssueSingleCert(vo);
        try (FileWriter cert = new FileWriter(storePath + "sm2SelfIssue.pem");
             FileWriter key = new FileWriter(storePath + "sm2SelfIssue.key")) {
            cert.write(certWithPrivateKey.cert());
            key.write(certWithPrivateKey.privateKey());
        }
    }

    /**
     * sm2 自签双证书
     * ca false
     * key 没密码
     */
    @Test
    void sm2SelfIssueDoubleSiteCertificate() throws IOException {
        String commonName = "www.site.com";

        SelfIssueCertVO vo = new SelfIssueCertVO();
        X500Name siteDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", commonName);
        vo.setSubjectDn(siteDn);
        vo.setCa(false);
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年
        vo.setNotBefore(notBefore);
        vo.setNotAfter(notAfter);
        vo.setSubjectAltNames(Collections.singletonList(commonName));
        DoubleCertWithDoublePrivateKey doubleCertWithDoublePrivateKey = sm2CertService.selfIssueDoubleCert(vo);
        try (FileWriter sigCert = new FileWriter(storePath + "sm2SelfIssueSig.pem");
             FileWriter sigKey = new FileWriter(storePath + "sm2SelfIssueSig.key");
             FileWriter encCert = new FileWriter(storePath + "sm2SelfIssueEnc.pem");
             FileWriter encKey = new FileWriter(storePath + "sm2SelfIssueEnc.key")) {
            sigCert.write(doubleCertWithDoublePrivateKey.sigCert());
            sigKey.write(doubleCertWithDoublePrivateKey.sigPrivateKey());
            encCert.write(doubleCertWithDoublePrivateKey.encCert());
            encKey.write(doubleCertWithDoublePrivateKey.encPrivateKey());
        }
    }

    /**
     * sm2 ca签发的双证书
     */
    @Test
    void sm2CaIssueDoubleCertificate() throws IOException {
        String caCommonName = "SM2ROOTCA";
        String user1 = "user1";

        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年
        SelfIssueCertVO svo = new SelfIssueCertVO();
        svo.setCa(true);
        svo.setNotBefore(notBefore);
        svo.setNotAfter(notAfter);
        X500Name caDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", caCommonName);
        svo.setSubjectDn(caDn);
        svo.setSubjectAltNames(Collections.singletonList(caCommonName));
        CertWithPrivateKey caCertWithPrivateKey = sm2CertService.selfIssueSingleCert(svo);

        String[] user1Materials = caIssue(false, user1, caCertWithPrivateKey.cert(), caCertWithPrivateKey.privateKey(), sm2CertService);

        try (FileWriter caPem = new FileWriter(storePath + "sm2rootca.pem");
             FileWriter caKey = new FileWriter(storePath + "sm2rootca.key");
             FileWriter user1PemSig = new FileWriter(storePath + "sm2CaIssueUser1Sig.pem");
             FileWriter user1KeySig = new FileWriter(storePath + "sm2CaIssueUser1Sig.key");
             FileWriter user1PemEnc = new FileWriter(storePath + "sm2CaIssueUser1Enc.pem");
             FileWriter user1KeyEnc = new FileWriter(storePath + "sm2CaIssueUser1Enc.key")) {
            caPem.write(caCertWithPrivateKey.cert());
            caKey.write(caCertWithPrivateKey.privateKey());
            user1PemSig.write(user1Materials[0]);
            user1KeySig.write(user1Materials[1]);
            user1PemEnc.write(user1Materials[2]);
            user1KeyEnc.write(user1Materials[3]);
        }
    }

    /**
     * sm2 ca签发的双证书(信封版本)
     */
    @Test
    void sm2CaIssueDoubleCertificateEnvelop() throws IOException {
        String path = storePath + "密钥不落地/";
        String p10 = """
                -----BEGIN CERTIFICATE REQUEST-----
                MIIBAzCBpwIBADAjMQswCQYDVQQGEwJDTjEUMBIGA1UEAwwLMTAuMC4yNDcuNzYw
                WTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATLwTOS88RE6V8wctETm54dRGw7XJM9
                P0+qns5PHScp6dcs8w/C2pnR7pLkzHrKpcsEwbPucRKFcTWxF/mvUG3YoCIwIAYJ
                KoZIhvcNAQkOMRMwETAPBgNVHREECDAGhwQKAPdMMAwGCCqBHM9VAYN1BQADSQAw
                RgIhAKQqKOTbrn681CQyS7tCIClXjMSb5AI/ogcVSCnjtwxzAiEA7nBToM8PaV9X
                wxBlZrCvXDVRRYrf3gH0+GPMHF8h+Uo=
                -----END CERTIFICATE REQUEST-----""";
        String caCommonName = "SM2ROOTCA";

        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年
        SelfIssueCertVO svo = new SelfIssueCertVO();
        X500Name caDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", caCommonName);
        svo.setSubjectDn(caDn);
        svo.setCa(false);
        svo.setNotBefore(notBefore);
        svo.setNotAfter(notAfter);
        svo.setSubjectAltNames(Collections.singletonList(caCommonName));
        CertWithPrivateKey caCertWithPrivateKey = sm2CertService.selfIssueSingleCert(svo);

        CaIssueCertVO cvo = new CaIssueCertVO();
        cvo.setCa(false);
        cvo.setNotBefore(notBefore);
        cvo.setNotAfter(notAfter);
        cvo.setCsr(p10);
        cvo.setCaCert(caCertWithPrivateKey.cert());
        cvo.setCaPrivateKey(caCertWithPrivateKey.privateKey());
        DoubleCertWithEnvelop doubleCertWithEnvelop = sm2CertService.caIssueDoubleCertWithEnvelop(cvo);
        try (FileWriter caPem = new FileWriter(path + "ca.pem");
             FileWriter caKey = new FileWriter(path + "ca.key");
             FileWriter sig = new FileWriter(path + "sm2sig.pem");
             FileWriter enc = new FileWriter(path + "sm2enc.pem");
             FileWriter envelop = new FileWriter(path + "sm2envelop.key")) {
            caPem.write(caCertWithPrivateKey.cert());
            caKey.write(caCertWithPrivateKey.privateKey());
            sig.write(doubleCertWithEnvelop.sigCert());
            enc.write(doubleCertWithEnvelop.encCert());
            envelop.write(doubleCertWithEnvelop.envelop());
        }
    }

    /**
     * ecc 自签
     * ca false
     * 签名+加密
     * key 没密码
     */
    @Test
    void eccSelfIssueSingleCert() throws IOException {
        String commonName = "www.site.com";

        SelfIssueCertVO vo = new SelfIssueCertVO();
        X500Name siteDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", commonName);
        vo.setSubjectDn(siteDn);
        vo.setCa(false);
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年
        vo.setNotBefore(notBefore);
        vo.setNotAfter(notAfter);
        vo.setSubjectAltNames(Collections.singletonList(commonName));
        CertWithPrivateKey certWithPrivateKey = eccCertService.selfIssueSingleCert(vo);
        try (FileWriter cert = new FileWriter(storePath + "eccSelfIssue.pem");
             FileWriter key = new FileWriter(storePath + "eccSelfIssue.key")) {
            cert.write(certWithPrivateKey.cert());
            key.write(certWithPrivateKey.privateKey());
        }
    }

    /**
     * rsa 自签
     * ca false
     * 签名+加密
     * key 没密码
     */
    @Test
    void rsaSelfIssueSingleCert() throws IOException {
        String commonName = "www.site.com";

        SelfIssueCertVO vo = new SelfIssueCertVO();
        X500Name siteDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", commonName);
        vo.setSubjectDn(siteDn);
        vo.setCa(false);
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年
        vo.setNotBefore(notBefore);
        vo.setNotAfter(notAfter);
        vo.setSubjectAltNames(Collections.singletonList(commonName));
        CertWithPrivateKey certWithPrivateKey = rsaCertService.selfIssueSingleCert(vo);
        try (FileWriter cert = new FileWriter(storePath + "rsaSelfIssue.pem");
             FileWriter key = new FileWriter(storePath + "rsaSelfIssue.key")) {
            cert.write(certWithPrivateKey.cert());
            key.write(certWithPrivateKey.privateKey());
        }
    }

    @Test
    void rsaCaIssueSingleCertificate() throws IOException {
        String caCommonName = "RSAROOTCA";
        String user1 = "user1";
//        String user2 = "user2";

        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年
        SelfIssueCertVO svo = new SelfIssueCertVO();
        svo.setCa(true);
        svo.setNotBefore(notBefore);
        svo.setNotAfter(notAfter);
        X500Name caDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", caCommonName);
        svo.setSubjectDn(caDn);
        svo.setSubjectAltNames(Collections.singletonList(caCommonName));
        CertWithPrivateKey caCertWithPrivateKey = rsaCertService.selfIssueSingleCert(svo);

        String[] user1Materials = caIssue(true, user1, caCertWithPrivateKey.cert(), caCertWithPrivateKey.privateKey(), rsaCertService);

        try (FileWriter caPem = new FileWriter(storePath + "rsarootca.pem");
             FileWriter caKey = new FileWriter(storePath + "rsarootca.key");
             FileWriter user1Pem = new FileWriter(storePath + "rsaCaIssueUser1.pem");
             FileWriter user1Key = new FileWriter(storePath + "rsaCaIssueUser1.key")) {
            caPem.write(caCertWithPrivateKey.cert());
            caKey.write(caCertWithPrivateKey.privateKey());
            user1Pem.write(user1Materials[0]);
            user1Key.write(user1Materials[1]);
        }
    }

    private String[] caIssue(boolean isSingle, String commonName, String caCert, String caKey, AbstractCertService certService) {
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年
        CsrVO csrvo = new CsrVO();
        X500Name siteDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", commonName);
        csrvo.setSubjectDn(siteDn);
        List<String> sans = Collections.singletonList(commonName);
        csrvo.setSubjectAltNames(sans);
        CsrWithPrivateKey csrWithPrivateKey = certService.generateCsr(csrvo);
        CaIssueCertVO cvo = new CaIssueCertVO();
        cvo.setCa(false);
        cvo.setNotBefore(notBefore);
        cvo.setNotAfter(notAfter);
        cvo.setCsr(csrWithPrivateKey.csr());
        cvo.setCaCert(caCert);
        cvo.setCaPrivateKey(caKey);
        if (isSingle) {
            String cert = certService.caIssueSingleCert(cvo);
            return new String[]{cert, csrWithPrivateKey.privateKey()};
        } else {
            DoubleCertWithPrivateKey doubleCertWithPrivateKey = certService.caIssueDoubleCert(cvo);
            return new String[]{doubleCertWithPrivateKey.sigCert(), csrWithPrivateKey.privateKey(), doubleCertWithPrivateKey.encCert(), doubleCertWithPrivateKey.encPrivateKey()};
        }
    }

}
