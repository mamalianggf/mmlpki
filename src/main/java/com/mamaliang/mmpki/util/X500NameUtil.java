package com.mamaliang.mmpki.util;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

/**
 * @author gaof
 * @date 2024/3/1
 */
public class X500NameUtil {

    public static X500Name generateX500Name(String country, String stateOrProvince, String locality, String organization, String organizationUnit, String commonName) {
        return new X500NameBuilder()
                .addRDN(BCStyle.C, country)
                .addRDN(BCStyle.ST, stateOrProvince)
                .addRDN(BCStyle.L, locality)
                .addRDN(BCStyle.O, organization)
                .addRDN(BCStyle.OU, organizationUnit)
                .addRDN(BCStyle.CN, commonName)
                .build();
    }
}
