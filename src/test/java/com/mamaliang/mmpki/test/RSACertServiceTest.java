package com.mamaliang.mmpki.test;

import com.mamaliang.mmpki.CertServiceTool;
import com.mamaliang.mmpki.cert.model.CertWithPrivateKey;
import com.mamaliang.mmpki.cert.service.impl.RSACertServiceImpl;
import com.mamaliang.mmpki.model.CaWithOneSite;
import com.mamaliang.mmpki.util.PemUtil;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Certificate;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;


class RSACertServiceTest {

    @Test
    void testSelfIssueSiteCertificate() throws IOException {
        CertWithPrivateKey certWithPrivateKey = CertServiceTool.selfIssueSiteCertificate(new RSACertServiceImpl());
        Certificate certificate = PemUtil.pem2Cert(certWithPrivateKey.cert());
        RDN[] rdNs = certificate.getSubject().getRDNs(BCStyle.CN);
        Assertions.assertEquals("www.site.com", rdNs[0].getTypesAndValues()[0].getValue().toString());
    }

    @Test
    void testCaIssueSiteCertificate() throws IOException {
        CaWithOneSite caWithOneSite = CertServiceTool.caIssueSiteCertificate(new RSACertServiceImpl());
        Certificate certificate = PemUtil.pem2Cert(caWithOneSite.site().cert());
        RDN[] rdNs = certificate.getSubject().getRDNs(BCStyle.CN);
        Assertions.assertEquals("www.site.com", rdNs[0].getTypesAndValues()[0].getValue().toString());
    }
}
