package com.mamaliang.mmpki.cert.vo;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

/**
 * @author gaof
 * @date 2023/11/18
 */
public class X500NameVO {

    private String country;

    private String stateOrProvince;

    private String locality;

    private String organization;

    private String organizationUnit;

    private String commonName;

    public X500Name generateX500Name() {
        return new X500NameBuilder()
                .addRDN(BCStyle.C, country)
                .addRDN(BCStyle.ST, stateOrProvince)
                .addRDN(BCStyle.L, locality)
                .addRDN(BCStyle.O, organization)
                .addRDN(BCStyle.OU, organizationUnit)
                .addRDN(BCStyle.CN, commonName)
                .build();
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public String getStateOrProvince() {
        return stateOrProvince;
    }

    public void setStateOrProvince(String stateOrProvince) {
        this.stateOrProvince = stateOrProvince;
    }

    public String getLocality() {
        return locality;
    }

    public void setLocality(String locality) {
        this.locality = locality;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    public String getOrganizationUnit() {
        return organizationUnit;
    }

    public void setOrganizationUnit(String organizationUnit) {
        this.organizationUnit = organizationUnit;
    }

    public String getCommonName() {
        return commonName;
    }

    public void setCommonName(String commonName) {
        this.commonName = commonName;
    }

}
