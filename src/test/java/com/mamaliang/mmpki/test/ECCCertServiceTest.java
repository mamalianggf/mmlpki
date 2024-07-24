package com.mamaliang.mmpki.test;

import com.mamaliang.mmpki.cert.model.*;
import com.mamaliang.mmpki.cert.service.impl.ECCCertServiceImpl;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.function.Function;


class ECCCertServiceTest {

    @Test
    void testSelfIssueSiteCertificate() throws IOException {

        Function<SelfIssueCertVO, CertWithPrivateKey> issue = vo -> new ECCCertServiceImpl().selfIssueSingleCert(vo);

        CertServiceTestTool.testSelfIssueSiteCertificate(issue);
    }

    @Test
    void testCaIssueSiteCertificate() throws IOException {

        Function<SelfIssueCertVO, CertWithPrivateKey> issueCa = svo -> new ECCCertServiceImpl().selfIssueSingleCert(svo);
        Function<CsrVO, CsrWithPrivateKey> issueCsr = csrvo -> new ECCCertServiceImpl().generateCsr(csrvo);
        Function<CaIssueCertVO, String> caIssue = cvo -> new ECCCertServiceImpl().caIssueSingleCert(cvo);

        CertServiceTestTool.testCaIssueSiteCertificate(issueCa, issueCsr, caIssue);
    }
}
