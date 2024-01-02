package com.mamaliang.mmpki.cert.service;

import com.mamaliang.mmpki.cert.vo.CSRVO;

/**
 * @author gaof
 * @date 2023/11/17
 */
public interface CSRService {

    /**
     * 签发 p10 证书请求
     *
     * @param csrvo 证书请求中的项
     * @return 顺序如下
     * index 0 p10 pem;
     * index 1 privateKey pem
     */
    String[] generateCSR(CSRVO csrvo);

}
