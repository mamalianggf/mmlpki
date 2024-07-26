package com.mamaliang.mmpki.nsagTool;

import com.mamaliang.mmpki.CertServiceTool;
import com.mamaliang.mmpki.cert.model.*;
import com.mamaliang.mmpki.cert.service.impl.ECCCertServiceImpl;
import com.mamaliang.mmpki.cert.service.impl.RSACertServiceImpl;
import com.mamaliang.mmpki.cert.service.impl.SM2CertServiceImpl;
import com.mamaliang.mmpki.model.CaWithTwoSite;
import com.mamaliang.mmpki.util.X500NameUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.FileWriter;
import java.io.IOException;
import java.util.Collections;
import java.util.Date;

/**
 * @author gaof
 * @date 2023/12/29
 */
@Disabled
public class CertTest {

    private final String storePath = "/Users/mamaliang/Workspace/mmlpki/db/";

    @Test
    void sm2SelfIssueSingleCert() throws IOException {
        CertWithPrivateKey certWithPrivateKey = CertServiceTool.selfIssueSiteCertificate(new SM2CertServiceImpl());
        try (FileWriter cert = new FileWriter(storePath + "sm2SelfIssue.pem");
             FileWriter key = new FileWriter(storePath + "sm2SelfIssue.key")) {
            cert.write(certWithPrivateKey.cert());
            key.write(certWithPrivateKey.privateKey());
        }
    }

    @Test
    void rsaSelfIssueSingleCert() throws IOException {
        CertWithPrivateKey certWithPrivateKey = CertServiceTool.selfIssueSiteCertificate(new RSACertServiceImpl());
        try (FileWriter cert = new FileWriter(storePath + "rsaSelfIssue.pem");
             FileWriter key = new FileWriter(storePath + "rsaSelfIssue.key")) {
            cert.write(certWithPrivateKey.cert());
            key.write(certWithPrivateKey.privateKey());
        }
    }

    @Test
    void eccSelfIssueSingleCert() throws IOException {
        CertWithPrivateKey certWithPrivateKey = CertServiceTool.selfIssueSiteCertificate(new ECCCertServiceImpl());
        try (FileWriter cert = new FileWriter(storePath + "eccSelfIssue.pem");
             FileWriter key = new FileWriter(storePath + "eccSelfIssue.key")) {
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
        DoubleCertWithDoublePrivateKey doubleCertWithDoublePrivateKey = CertServiceTool.selfIssueDoubleSiteCertificate(new SM2CertServiceImpl());
        try (FileWriter sigCert = new FileWriter(storePath + "sm2SelfIssueSig.pem");
             FileWriter sigKey = new FileWriter(storePath + "sm2SelfIssueSig.key");
             FileWriter encCert = new FileWriter(storePath + "sm2SelfIssueEnc.pem");
             FileWriter encKey = new FileWriter(storePath + "sm2SelfIssueEnc.key")) {
            sigCert.write(doubleCertWithDoublePrivateKey.sig().cert());
            sigKey.write(doubleCertWithDoublePrivateKey.sig().privateKey());
            encCert.write(doubleCertWithDoublePrivateKey.enc().cert());
            encKey.write(doubleCertWithDoublePrivateKey.enc().privateKey());
        }
    }

    /**
     * sm2 ca签发的双证书
     */
    @Test
    void sm2CaIssueDoubleCertificate() throws IOException {
        CaWithTwoSite caWithTwoSite = CertServiceTool.caIssueDoubleSiteCertificate(new SM2CertServiceImpl());
        try (FileWriter caPem = new FileWriter(storePath + "sm2rootca.pem");
             FileWriter caKey = new FileWriter(storePath + "sm2rootca.key");
             FileWriter user1PemSig = new FileWriter(storePath + "sm2CaIssueUser1Sig.pem");
             FileWriter user1KeySig = new FileWriter(storePath + "sm2CaIssueUser1Sig.key");
             FileWriter user1PemEnc = new FileWriter(storePath + "sm2CaIssueUser1Enc.pem");
             FileWriter user1KeyEnc = new FileWriter(storePath + "sm2CaIssueUser1Enc.key")) {
            caPem.write(caWithTwoSite.ca().cert());
            caKey.write(caWithTwoSite.ca().privateKey());
            user1PemSig.write(caWithTwoSite.sigSite().cert());
            user1KeySig.write(caWithTwoSite.sigSite().privateKey());
            user1PemEnc.write(caWithTwoSite.encSite().cert());
            user1KeyEnc.write(caWithTwoSite.encSite().privateKey());
        }
    }

    /**
     * sm2 ca签发的双证书(信封版本)
     */
    @Test
    void sm2CaIssueDoubleCertificateEnvelop() throws IOException {
        String path = storePath + "密钥不落地/";
        String caCommonName = "SM2ROOTCA";
        String p10 = """
                -----BEGIN CERTIFICATE REQUEST-----
                MIIBAzCBpwIBADAjMQswCQYDVQQGEwJDTjEUMBIGA1UEAwwLMTAuMC4yNDcuNzYw
                WTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATLwTOS88RE6V8wctETm54dRGw7XJM9
                P0+qns5PHScp6dcs8w/C2pnR7pLkzHrKpcsEwbPucRKFcTWxF/mvUG3YoCIwIAYJ
                KoZIhvcNAQkOMRMwETAPBgNVHREECDAGhwQKAPdMMAwGCCqBHM9VAYN1BQADSQAw
                RgIhAKQqKOTbrn681CQyS7tCIClXjMSb5AI/ogcVSCnjtwxzAiEA7nBToM8PaV9X
                wxBlZrCvXDVRRYrf3gH0+GPMHF8h+Uo=
                -----END CERTIFICATE REQUEST-----""";

        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年
        SelfIssueCertVO svo = new SelfIssueCertVO();
        X500Name caDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", caCommonName);
        svo.setSubjectDn(caDn);
        svo.setCa(false);
        svo.setNotBefore(notBefore);
        svo.setNotAfter(notAfter);
        svo.setSubjectAltNames(Collections.singletonList(caCommonName));
        CertWithPrivateKey caCertWithPrivateKey = new SM2CertServiceImpl().selfIssueSingleCert(svo);

        CaIssueCertVO cvo = new CaIssueCertVO();
        cvo.setCa(false);
        cvo.setNotBefore(notBefore);
        cvo.setNotAfter(notAfter);
        cvo.setCsr(p10);
        cvo.setCaCert(caCertWithPrivateKey.cert());
        cvo.setCaPrivateKey(caCertWithPrivateKey.privateKey());
        DoubleCertWithEnvelop doubleCertWithEnvelop = new SM2CertServiceImpl().caIssueDoubleCertWithEnvelop(cvo);
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

}
