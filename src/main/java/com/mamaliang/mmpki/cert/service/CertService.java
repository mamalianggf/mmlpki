package com.mamaliang.mmpki.cert.service;

import com.mamaliang.mmpki.cert.vo.CaIssueCertVO;
import com.mamaliang.mmpki.cert.vo.SelfIssueCertVO;

/**
 * @author gaof
 * @date 2023/11/17
 */
public interface CertService {

    /**
     * 自签发单证书
     *
     * @param selfIssueCertVO selfIssueCertVO
     * @return 顺序如下
     * index 0 cert pem;
     * index 1 privateKey pem
     */
    String[] selfIssueSingleCert(SelfIssueCertVO selfIssueCertVO);

    /**
     * 自签发双证书
     *
     * @param selfIssueCertVO selfIssueCertVO
     * @return 顺序如下
     * index 0 sign cert pem;
     * index 1 sign privateKey pem;
     * index 2 enc cert pem;
     * index 3 enc privateKey pem
     */
    String[] selfIssueDoubleCert(SelfIssueCertVO selfIssueCertVO);

    /**
     * ca签发单证书
     *
     * @param caIssueCertVO caIssueCertVO
     * @return cert pem
     */
    String caIssueSingleCert(CaIssueCertVO caIssueCertVO);

    /**
     * ca签发双证书
     *
     * @param caIssueCertVO caIssueCertVO
     * @return 顺序如下
     * index 0 sign cert pem;
     * index 1 enc cert pem;
     * index 2 enc privateKey pem
     */
    String[] caIssueDoubleCert(CaIssueCertVO caIssueCertVO);

    /**
     * ca签发双证书,密钥不落地,0016规范信封
     *
     * @param caIssueCertVO caIssueCertVO
     * @return 顺序如下
     * index 0 sign cert pem;
     * index 1 enc cert pem;
     * index 2 envelop
     */
    String[] caIssueDoubleCertWithEnvelop(CaIssueCertVO caIssueCertVO);

}
