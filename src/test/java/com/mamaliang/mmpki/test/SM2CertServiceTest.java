package com.mamaliang.mmpki.test;

import com.mamaliang.mmpki.CertServiceTool;
import com.mamaliang.mmpki.cert.model.CertWithPrivateKey;
import com.mamaliang.mmpki.cert.model.DoubleCertWithDoublePrivateKey;
import com.mamaliang.mmpki.cert.service.impl.SM2CertServiceImpl;
import com.mamaliang.mmpki.model.CaWithOneSite;
import com.mamaliang.mmpki.model.CaWithTwoSite;
import com.mamaliang.mmpki.model.CaWithTwoSiteEnvelop;
import com.mamaliang.mmpki.util.PemUtil;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Certificate;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;

/**
 * @author gaof
 * @date 2023/10/30
 */
public class SM2CertServiceTest {

    @Test
    void testSelfIssueSiteCertificate() throws IOException {
        CertWithPrivateKey certWithPrivateKey = CertServiceTool.selfIssueSiteCertificate(new SM2CertServiceImpl());
        Certificate certificate = PemUtil.pem2Cert(certWithPrivateKey.cert());
        RDN[] rdNs = certificate.getSubject().getRDNs(BCStyle.CN);
        Assertions.assertEquals("www.site.com", rdNs[0].getTypesAndValues()[0].getValue().toString());
    }

    @Test
    void testCaIssueSiteCertificate() throws IOException {
        CaWithOneSite caWithOneSite = CertServiceTool.caIssueSiteCertificate(new SM2CertServiceImpl());
        Certificate certificate = PemUtil.pem2Cert(caWithOneSite.site().cert());
        RDN[] rdNs = certificate.getSubject().getRDNs(BCStyle.CN);
        Assertions.assertEquals("www.site.com", rdNs[0].getTypesAndValues()[0].getValue().toString());
    }

    @Test
    void testSelfIssueDoubleSiteCertificate() throws IOException {
        DoubleCertWithDoublePrivateKey doubleCertWithDoublePrivateKey = CertServiceTool.selfIssueDoubleSiteCertificate(new SM2CertServiceImpl());
        Certificate sigCert = PemUtil.pem2Cert(doubleCertWithDoublePrivateKey.sig().cert());
        RDN[] sigRdNs = sigCert.getSubject().getRDNs(BCStyle.CN);
        Assertions.assertEquals("www.site.com", sigRdNs[0].getTypesAndValues()[0].getValue().toString());
        Certificate encCert = PemUtil.pem2Cert(doubleCertWithDoublePrivateKey.enc().cert());
        RDN[] encRdNs = encCert.getSubject().getRDNs(BCStyle.CN);
        Assertions.assertEquals("www.site.com", encRdNs[0].getTypesAndValues()[0].getValue().toString());
    }


    @Test
    void testCaIssueDoubleSiteCertificate() throws IOException {
        CaWithTwoSite caWithTwoSite = CertServiceTool.caIssueDoubleSiteCertificate(new SM2CertServiceImpl());
        Certificate sigCert = PemUtil.pem2Cert(caWithTwoSite.sigSite().cert());
        RDN[] sigRdNs = sigCert.getSubject().getRDNs(BCStyle.CN);
        Assertions.assertEquals("www.site.com", sigRdNs[0].getTypesAndValues()[0].getValue().toString());
        Certificate encCert = PemUtil.pem2Cert(caWithTwoSite.encSite().cert());
        RDN[] encRdNs = encCert.getSubject().getRDNs(BCStyle.CN);
        Assertions.assertEquals("www.site.com", encRdNs[0].getTypesAndValues()[0].getValue().toString());
    }

    @Test
    void testCaIssueDoubleCertWithEnvelop() throws Exception {
        CaWithTwoSiteEnvelop caWithTwoSiteEnvelop = CertServiceTool.caIssueDoubleCertWithEnvelop(new SM2CertServiceImpl());
        Certificate sigCert = PemUtil.pem2Cert(caWithTwoSiteEnvelop.sigSite().cert());
        RDN[] sigRdNs = sigCert.getSubject().getRDNs(BCStyle.CN);
        Assertions.assertEquals("www.site.com", sigRdNs[0].getTypesAndValues()[0].getValue().toString());
        Certificate encCert = PemUtil.pem2Cert(caWithTwoSiteEnvelop.encSiteCert());
        RDN[] encRdNs = encCert.getSubject().getRDNs(BCStyle.CN);
        Assertions.assertEquals("www.site.com", encRdNs[0].getTypesAndValues()[0].getValue().toString());
    }

}
