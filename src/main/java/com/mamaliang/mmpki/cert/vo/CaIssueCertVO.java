package com.mamaliang.mmpki.cert.vo;

import lombok.Getter;
import lombok.Setter;

import java.util.Date;

/**
 * @author gaof
 * @date 2023/11/17
 */
@Getter
@Setter
public class CaIssueCertVO {

    private boolean isCa;

    private Date notBefore;

    private Date notAfter;

    private String csr;

    private String caCert;

    private String caPrivateKey;
}
