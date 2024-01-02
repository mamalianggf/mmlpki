package com.mamaliang.mmpki.cert.vo;

import java.util.Date;

/**
 * @author gaof
 * @date 2023/11/17
 */
public class CaIssueCertVO {

    private boolean isCa;

    private Date notBefore;

    private Date notAfter;

    private String csr;

    private String caCert;

    private String caPrivateKey;


    public Date getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(Date notBefore) {
        this.notBefore = notBefore;
    }

    public Date getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(Date notAfter) {
        this.notAfter = notAfter;
    }

    public boolean isCa() {
        return isCa;
    }

    public void setCa(boolean ca) {
        isCa = ca;
    }

    public String getCsr() {
        return csr;
    }

    public void setCsr(String csr) {
        this.csr = csr;
    }

    public String getCaCert() {
        return caCert;
    }

    public void setCaCert(String caCert) {
        this.caCert = caCert;
    }

    public String getCaPrivateKey() {
        return caPrivateKey;
    }

    public void setCaPrivateKey(String caPrivateKey) {
        this.caPrivateKey = caPrivateKey;
    }
}
