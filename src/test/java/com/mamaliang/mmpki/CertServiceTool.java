package com.mamaliang.mmpki;

import com.mamaliang.mmpki.cert.model.*;
import com.mamaliang.mmpki.cert.service.AbstractCertService;
import com.mamaliang.mmpki.model.CaWithOneSite;
import com.mamaliang.mmpki.model.CaWithTwoSite;
import com.mamaliang.mmpki.model.CaWithTwoSiteEnvelop;
import com.mamaliang.mmpki.util.X500NameUtil;
import org.bouncycastle.asn1.x500.X500Name;

import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * @author gaof
 * @date 2024/7/24
 */
public class CertServiceTool {

    public static CertWithPrivateKey selfIssueSiteCertificate(AbstractCertService abstractCertService) {
        SelfIssueCertVO vo = new SelfIssueCertVO();
        X500Name siteDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "www.site.com");
        vo.setSubjectDn(siteDn);
        vo.setCa(false);
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年
        vo.setNotBefore(notBefore);
        vo.setNotAfter(notAfter);
        vo.setSubjectAltNames(Collections.singletonList("www.site.com"));
        return abstractCertService.selfIssueSingleCert(vo);
    }

    public static CaWithOneSite caIssueSiteCertificate(AbstractCertService abstractCertService) {
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年
        SelfIssueCertVO svo = new SelfIssueCertVO();
        svo.setCa(false);
        svo.setNotBefore(notBefore);
        svo.setNotAfter(notAfter);
        X500Name caDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "ROOT_CA");
        svo.setSubjectDn(caDn);
        svo.setSubjectAltNames(Collections.singletonList("ROOT_CA"));
        CertWithPrivateKey caCertWithPrivateKey = abstractCertService.selfIssueSingleCert(svo);
        CsrVO csrvo = new CsrVO();
        X500Name siteDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "www.site.com");
        csrvo.setSubjectDn(siteDn);
        List<String> sans = Collections.singletonList("www.site.com");
        csrvo.setSubjectAltNames(sans);
        CsrWithPrivateKey csrWithPrivateKey = abstractCertService.generateCsr(csrvo);

        CaIssueCertVO cvo = new CaIssueCertVO();
        cvo.setCa(false);
        cvo.setNotBefore(notBefore);
        cvo.setNotAfter(notAfter);
        cvo.setCsr(csrWithPrivateKey.csr());
        cvo.setCaCert(caCertWithPrivateKey.cert());
        cvo.setCaPrivateKey(caCertWithPrivateKey.privateKey());
        String cert = abstractCertService.caIssueSingleCert(cvo);

        CertWithPrivateKey site = new CertWithPrivateKey(cert, csrWithPrivateKey.privateKey());
        return new CaWithOneSite(caCertWithPrivateKey, site);


    }

    public static DoubleCertWithDoublePrivateKey selfIssueDoubleSiteCertificate(AbstractCertService abstractCertService) {
        SelfIssueCertVO vo = new SelfIssueCertVO();
        X500Name siteDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "www.site.com");
        vo.setSubjectDn(siteDn);
        vo.setCa(false);
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年
        vo.setNotBefore(notBefore);
        vo.setNotAfter(notAfter);
        vo.setSubjectAltNames(Collections.singletonList("www.site.com"));
        return abstractCertService.selfIssueDoubleCert(vo);
    }

    public static CaWithTwoSite caIssueDoubleSiteCertificate(AbstractCertService abstractCertService) {
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年

        SelfIssueCertVO svo = new SelfIssueCertVO();
        X500Name caDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "ROOT_CA");
        svo.setSubjectDn(caDn);
        svo.setCa(false);
        svo.setNotBefore(notBefore);
        svo.setNotAfter(notAfter);
        svo.setSubjectAltNames(Collections.singletonList("ROOT_CA"));
        CertWithPrivateKey caCertWithPrivateKey = abstractCertService.selfIssueSingleCert(svo);

        CsrVO csrvo = new CsrVO();
        X500Name siteDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "www.site.com");
        csrvo.setSubjectDn(siteDn);
        List<String> sans = Collections.singletonList("www.site.com");
        csrvo.setSubjectAltNames(sans);
        CsrWithPrivateKey csrWithPrivateKey = abstractCertService.generateCsr(csrvo);

        CaIssueCertVO cvo = new CaIssueCertVO();
        cvo.setCa(false);
        cvo.setNotBefore(notBefore);
        cvo.setNotAfter(notAfter);
        cvo.setCsr(csrWithPrivateKey.csr());
        cvo.setCaCert(caCertWithPrivateKey.cert());
        cvo.setCaPrivateKey(caCertWithPrivateKey.privateKey());
        DoubleCertWithPrivateKey doubleCertWithPrivateKey = abstractCertService.caIssueDoubleCert(cvo);

        CertWithPrivateKey sig = new CertWithPrivateKey(doubleCertWithPrivateKey.sigCert(), csrWithPrivateKey.privateKey());
        CertWithPrivateKey enc = new CertWithPrivateKey(doubleCertWithPrivateKey.encCert(), doubleCertWithPrivateKey.encPrivateKey());
        return new CaWithTwoSite(caCertWithPrivateKey, sig, enc);
    }

    public static CaWithTwoSiteEnvelop caIssueDoubleCertWithEnvelop(AbstractCertService abstractCertService) {
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年

        SelfIssueCertVO svo = new SelfIssueCertVO();
        X500Name caDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "ROOT_CA");
        svo.setSubjectDn(caDn);
        svo.setCa(false);
        svo.setNotBefore(notBefore);
        svo.setNotAfter(notAfter);
        svo.setSubjectAltNames(Collections.singletonList("ROOT_CA"));
        CertWithPrivateKey caCertWithPrivateKey = abstractCertService.selfIssueSingleCert(svo);

        CsrVO csrvo = new CsrVO();
        X500Name siteDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "www.site.com");
        csrvo.setSubjectDn(siteDn);
        List<String> sans = Collections.singletonList("www.site.com");
        csrvo.setSubjectAltNames(sans);
        CsrWithPrivateKey csrWithPrivateKey = abstractCertService.generateCsr(csrvo);

        CaIssueCertVO cvo = new CaIssueCertVO();
        cvo.setCa(false);
        cvo.setNotBefore(notBefore);
        cvo.setNotAfter(notAfter);
        cvo.setCsr(csrWithPrivateKey.csr());
        cvo.setCaCert(caCertWithPrivateKey.cert());
        cvo.setCaPrivateKey(caCertWithPrivateKey.privateKey());
        DoubleCertWithEnvelop doubleCertWithEnvelop = abstractCertService.caIssueDoubleCertWithEnvelop(cvo);

        CertWithPrivateKey sigSite = new CertWithPrivateKey(doubleCertWithEnvelop.sigCert(), csrWithPrivateKey.privateKey());
        return new CaWithTwoSiteEnvelop(caCertWithPrivateKey, sigSite, doubleCertWithEnvelop.encCert(), doubleCertWithEnvelop.envelop());
    }
}
