package com.mamaliang.mmpki.gmt0009;

import org.bouncycastle.asn1.*;

import java.util.Enumeration;

/**
 * @author gaof
 * @date 2023/12/27
 */
public class SM2Cipher extends ASN1Object {

    private final ASN1Integer x;
    private final ASN1Integer y;
    // 长度固定256位
    private final ASN1OctetString hash;
    // 与明文等长
    private final ASN1OctetString cipher;

    public SM2Cipher(ASN1Sequence seq) {
        Enumeration<?> objects = seq.getObjects();
        this.x = ASN1Integer.getInstance(objects.nextElement());
        this.y = ASN1Integer.getInstance(objects.nextElement());
        this.hash = ASN1OctetString.getInstance(objects.nextElement());
        this.cipher = ASN1OctetString.getInstance(objects.nextElement());
    }

    public ASN1Integer getX() {
        return x;
    }

    public ASN1Integer getY() {
        return y;
    }

    public ASN1OctetString getHash() {
        return hash;
    }

    public ASN1OctetString getCipher() {
        return cipher;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return null;
    }
}
