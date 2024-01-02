package com.mamaliang.mmpki.cert.vo;

import java.util.Date;
import java.util.List;

/**
 * @author gaof
 * @date 2023/11/17
 */
public class SelfIssueCertVO extends X500NameVO{

    private boolean isCa;

    private Date notBefore;

    private Date notAfter;

    private List<String> subjectAltNames;

    public boolean isCa() {
        return isCa;
    }

    public void setCa(boolean ca) {
        isCa = ca;
    }

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

    public List<String> getSubjectAltNames() {
        return subjectAltNames;
    }

    public void setSubjectAltNames(List<String> subjectAltNames) {
        this.subjectAltNames = subjectAltNames;
    }

}
