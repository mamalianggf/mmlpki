package com.mamaliang.mmpki.gmt0009;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.util.Enumeration;

/**
 * @author gaof
 * @date 2023/12/29
 */
public class SM2EnvelopedKey extends ASN1Object {

    private final AlgorithmIdentifier symAlgID;

    private final SM2Cipher sm2Cipher;

    // 内容为04||X||Y,其中X和Y分别表示公钥的x分量和y分量,其长度各为256位
    private final ASN1BitString sm2PublicKey;

    private final ASN1BitString sm2EncryptedPrivateKey;

    public SM2EnvelopedKey(ASN1Sequence seq) {
        Enumeration<?> objects = seq.getObjects();
        this.symAlgID = AlgorithmIdentifier.getInstance(objects.nextElement());
        this.sm2Cipher = new SM2Cipher(ASN1Sequence.getInstance(objects.nextElement()));
        this.sm2PublicKey = ASN1BitString.getInstance(objects.nextElement());
        this.sm2EncryptedPrivateKey = ASN1BitString.getInstance(objects.nextElement());
    }

    public AlgorithmIdentifier getSymAlgID() {
        return symAlgID;
    }

    public SM2Cipher getSm2Cipher() {
        return sm2Cipher;
    }

    public ASN1BitString getSm2PublicKey() {
        return sm2PublicKey;
    }

    public ASN1BitString getSm2EncryptedPrivateKey() {
        return sm2EncryptedPrivateKey;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return null;
    }
}
