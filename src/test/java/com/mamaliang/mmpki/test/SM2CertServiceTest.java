package com.mamaliang.mmpki.test;

import com.mamaliang.mmpki.cert.model.*;
import com.mamaliang.mmpki.cert.service.impl.SM2CertServiceImpl;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.function.Function;

/**
 * @author gaof
 * @date 2023/10/30
 */
public class SM2CertServiceTest {

    @Test
    void testSelfIssueSiteCertificate() throws IOException {

        Function<SelfIssueCertVO, CertWithPrivateKey> issue = vo -> new SM2CertServiceImpl().selfIssueSingleCert(vo);

        CertServiceTestTool.testSelfIssueSiteCertificate(issue);
    }

    @Test
    void testCaIssueSiteCertificate() throws IOException {

        Function<SelfIssueCertVO, CertWithPrivateKey> issueCa = svo -> new SM2CertServiceImpl().selfIssueSingleCert(svo);
        Function<CsrVO, CsrWithPrivateKey> issueCsr = csrvo -> new SM2CertServiceImpl().generateCsr(csrvo);
        Function<CaIssueCertVO, String> caIssue = cvo -> new SM2CertServiceImpl().caIssueSingleCert(cvo);

        CertServiceTestTool.testCaIssueSiteCertificate(issueCa, issueCsr, caIssue);
    }

    @Test
    void testSelfIssueDoubleSiteCertificate() throws IOException {

        Function<SelfIssueCertVO, DoubleCertWithDoublePrivateKey> issue = vo -> new SM2CertServiceImpl().selfIssueDoubleCert(vo);

        CertServiceTestTool.testSelfIssueDoubleSiteCertificate(issue);
    }


    @Test
    void testCaIssueDoubleSiteCertificate() throws IOException {

        Function<SelfIssueCertVO, CertWithPrivateKey> issueCa = svo -> new SM2CertServiceImpl().selfIssueSingleCert(svo);
        Function<CsrVO, CsrWithPrivateKey> issueCsr = csrvo -> new SM2CertServiceImpl().generateCsr(csrvo);
        Function<CaIssueCertVO, DoubleCertWithPrivateKey> caIssue = cvo -> new SM2CertServiceImpl().caIssueDoubleCert(cvo);

        CertServiceTestTool.testCaIssueDoubleSiteCertificate(issueCa, issueCsr, caIssue);
    }

    @Test
    void testCaIssueDoubleCertWithEnvelop() throws Exception {

        Function<SelfIssueCertVO, CertWithPrivateKey> issueCa = svo -> new SM2CertServiceImpl().selfIssueSingleCert(svo);
        Function<CsrVO, CsrWithPrivateKey> issueCsr = csrvo -> new SM2CertServiceImpl().generateCsr(csrvo);
        Function<CaIssueCertVO, DoubleCertWithEnvelop> caIssue = cvo -> new SM2CertServiceImpl().caIssueDoubleCertWithEnvelop(cvo);

        CertServiceTestTool.testCaIssueDoubleCertWithEnvelop(issueCa, issueCsr, caIssue);
    }

}
