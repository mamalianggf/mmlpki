package com.mamaliang.mmpki.cert.model;

import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.asn1.x500.X500Name;

import java.util.Date;
import java.util.List;

/**
 * @author gaof
 * @date 2023/11/17
 */
@Getter
@Setter
public class SelfIssueCertVO {

    private boolean isCa;

    private Date notBefore;

    private Date notAfter;

    private X500Name subjectDn;

    private List<String> subjectAltNames;

}
