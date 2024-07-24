package com.mamaliang.mmpki.test;

import com.mamaliang.mmpki.cert.model.*;
import com.mamaliang.mmpki.cert.service.impl.RSACertServiceImpl;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.function.Function;


class RSACertServiceTest {

    @Test
    void testSelfIssueSiteCertificate() throws IOException {

        Function<SelfIssueCertVO, CertWithPrivateKey> issue = vo -> new RSACertServiceImpl().selfIssueSingleCert(vo);

        CertServiceTestTool.testSelfIssueSiteCertificate(issue);
    }

    @Test
    void testCaIssueSiteCertificate() throws IOException {

        Function<SelfIssueCertVO, CertWithPrivateKey> issueCa = svo -> new RSACertServiceImpl().selfIssueSingleCert(svo);
        Function<CsrVO, CsrWithPrivateKey> issueCsr = csrvo -> new RSACertServiceImpl().generateCsr(csrvo);
        Function<CaIssueCertVO, String> caIssue = cvo -> new RSACertServiceImpl().caIssueSingleCert(cvo);

        CertServiceTestTool.testCaIssueSiteCertificate(issueCa, issueCsr, caIssue);
    }
}
