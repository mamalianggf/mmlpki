package com.mamaliang.mmpki.nsagTool;

import com.mamaliang.mmpki.algorithm.SM2;
import com.mamaliang.mmpki.util.PemUtil;
import com.mamaliang.mmpki.util.PropertiesUtil;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.FileWriter;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

/**
 * @author gaof
 * @date 2024/1/17
 */
@Disabled
public class KeyTest {

    private static final String STORE_PATH = PropertiesUtil.getString("cert.store.path");

    @Test
    void generateSm2Key() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        KeyPair keyPair = SM2.generateKeyPair();
        String privateKeyPem = PemUtil.privateKey2pem(keyPair.getPrivate());
        String publicKeyPem = PemUtil.publicKey2pem(keyPair.getPublic());

        try (FileWriter pri = new FileWriter(STORE_PATH + "sm2Private.pem");
             FileWriter pub = new FileWriter(STORE_PATH + "sm2Public.key")) {
            pri.write(privateKeyPem);
            pub.write(publicKeyPem);
        }
    }

    /**
     * 是否为非降级模式秘钥
     */
    @Test
    void isIndexModePrivateKey() {
        String key = """
                -----BEGIN PRIVATE KEY-----
                MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgghjcFaE/hvMzDhVX
                U3ETNG6cbX8LHYDDmXZvIkBe70WgCgYIKoEcz1UBgi2hRANCAASrDCyplnJr5dWs
                ngVw/cOKah27Mc1oErOH1vp6FNnSC+14mSHAldS0AiVcyf0mLwqDrYQ8/jEHFd0T
                5D2y/s0W
                -----END PRIVATE KEY-----""";
        try (PEMParser pemParser = new PEMParser(new StringReader(key))) {
            Object object = pemParser.readObject();
            if (object instanceof PrivateKeyInfo privateKeyInfo) {
                // vKey外层有个pKey
                ASN1Sequence pKey = ASN1Sequence.getInstance(privateKeyInfo.getEncoded());
                ASN1Sequence vKey = ASN1Sequence.getInstance(ASN1OctetString.getInstance(pKey.getObjectAt(2)).getOctets());
                int index = ASN1Integer.getInstance(vKey.getObjectAt(2)).getValue().intValue();
                System.out.println("this key is index mode key, index of key is " + index);
            } else {
                System.out.println("this key is not index mode key");
            }
        } catch (Exception e) {
            System.out.println("this key is not index mode key");
        }
    }


    /**
     * 用于更新密码机非降级模式下 私钥内部的索引值
     * <p>
     * PrivateKeyInfo ::= SEQUENCE {
     * version         Version,
     * privateKeyAlgorithm AlgorithmIdentifier,
     * privateKey      OCTET STRING,
     * attributes      [0] IMPLICIT Attributes OPTIONAL
     * }
     * <p>
     * typedef struct VKEY_PrivateKey_st {
     * ASN1_INTEGER        *version;                // 私钥版本号
     * ASN1_ENUMERATED     *type;                   // 私钥类型
     * ASN1_INTEGER        *index;                  // 私钥索引
     * ASN1_OCTET_STRING   *password;              // 私钥权限标识码
     * ASN1_BIT_STRING     *publicKey;             // 公钥信息
     * } VKEY_PrivateKey;
     */
    @Test
    void updateIndexWithIndexModePrivateKey() throws IOException {
        String key = """
                -----BEGIN PRIVATE KEY-----
                MGwCAQAwDgYKKwYBBAGBgVyaRQUABFcwVQIBAQoBAQIBBQQEcGFzc6FEA0IABPcc
                q+9oHDM46o6p11Je+30TMJij7RYPhr51sF9qOyRYd4lC0geijVNuBAm5tLgFpQT4
                NSnDVXh88XKDcNgD3uw=
                -----END PRIVATE KEY-----""";
        int oldIndex = 5;
        int newIndex = 1;

        try (PEMParser pemParser = new PEMParser(new StringReader(key))) {
            Object object = pemParser.readObject();

            if (object instanceof PrivateKeyInfo privateKeyInfo) {

                // vKey外层有个pKey
                ASN1Sequence pKey = ASN1Sequence.getInstance(privateKeyInfo.getEncoded());
                ASN1Sequence vKey = ASN1Sequence.getInstance(ASN1OctetString.getInstance(pKey.getObjectAt(2)).getOctets());

                int index = ASN1Integer.getInstance(vKey.getObjectAt(2)).getValue().intValue();
                if (oldIndex != index) {
                    System.out.println("index not matched,index in key is " + index);
                    return;
                }

                ASN1EncodableVector newVKeyVector = new ASN1EncodableVector();
                newVKeyVector.add(vKey.getObjectAt(0));
                newVKeyVector.add(vKey.getObjectAt(1));
                newVKeyVector.add(new ASN1Integer(BigInteger.valueOf(newIndex)));
                newVKeyVector.add(vKey.getObjectAt(3));
                newVKeyVector.add(vKey.getObjectAt(4));
                DERSequence newVKey = new DERSequence(newVKeyVector);

                ASN1EncodableVector newPKeyVector = new ASN1EncodableVector();
                newPKeyVector.add(pKey.getObjectAt(0));
                newPKeyVector.add(pKey.getObjectAt(1));
                newPKeyVector.add(new DEROctetString(newVKey.getEncoded()));
                DERSequence newPKey = new DERSequence(newPKeyVector);

                PrivateKeyInfo newPrivateKeyInfo = PrivateKeyInfo.getInstance(newPKey);

                PemObject pemObject = new PemObject("PRIVATE KEY", newPrivateKeyInfo.getEncoded());
                StringWriter stringWriter = new StringWriter();
                try (PemWriter pemWriter = new PemWriter(stringWriter)) {
                    pemWriter.writeObject(pemObject);
                }
                System.out.println(stringWriter);

            } else {
                System.out.println("PEM content is not a valid private key");
            }
        }
    }
}
