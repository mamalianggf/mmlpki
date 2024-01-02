package com.mamaliang.mmpki.cert.vo;

import java.util.List;

/**
 * @author gaof
 * @date 2023/11/17
 */
public class CSRVO extends X500NameVO {

    private List<String> subjectAltNames;

    public List<String> getSubjectAltNames() {
        return subjectAltNames;
    }

    public void setSubjectAltNames(List<String> subjectAltNames) {
        this.subjectAltNames = subjectAltNames;
    }
}
