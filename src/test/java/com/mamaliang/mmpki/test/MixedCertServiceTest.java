package com.mamaliang.mmpki.test;

import com.mamaliang.mmpki.cert.model.*;
import com.mamaliang.mmpki.cert.service.impl.RSACertServiceImpl;
import com.mamaliang.mmpki.cert.service.impl.SM2CertServiceImpl;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.function.Function;

/**
 * @author gaof
 * @date 2023/10/31
 */

public class MixedCertServiceTest {

    @Test
    void testRSACaIssueSM2Certificate() throws IOException {

        Function<SelfIssueCertVO, CertWithPrivateKey> issueCa = svo -> new RSACertServiceImpl().selfIssueSingleCert(svo);
        Function<CsrVO, CsrWithPrivateKey> issueCsr = csrvo -> new SM2CertServiceImpl().generateCsr(csrvo);
        Function<CaIssueCertVO, String> caIssue = cvo -> new RSACertServiceImpl().caIssueSingleCert(cvo);

        CertServiceTestTool.testCaIssueSiteCertificate(issueCa, issueCsr, caIssue);
    }

    @Test
    void testSM2CaIssueRSACertificate() throws IOException {

        Function<SelfIssueCertVO, CertWithPrivateKey> issueCa = svo -> new SM2CertServiceImpl().selfIssueSingleCert(svo);
        Function<CsrVO, CsrWithPrivateKey> issueCsr = csrvo -> new RSACertServiceImpl().generateCsr(csrvo);
        Function<CaIssueCertVO, String> caIssue = cvo -> new SM2CertServiceImpl().caIssueSingleCert(cvo);

        CertServiceTestTool.testCaIssueSiteCertificate(issueCa, issueCsr, caIssue);
    }

}
