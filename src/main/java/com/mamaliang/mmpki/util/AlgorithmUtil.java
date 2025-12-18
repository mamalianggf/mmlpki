package com.mamaliang.mmpki.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * @author gaof
 * @date 2025/5/16
 */
public class AlgorithmUtil {

    /**
     * 从AlgorithmIdentifier中提取摘要算法名称
     */
    private static String getDigestAlgorithm(AlgorithmIdentifier algId) {
        ASN1ObjectIdentifier oid = algId.getAlgorithm();
        // BC提供的映射关系
        if (oid.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption)) {
            return "SHA-256";
        } else if (oid.equals(PKCSObjectIdentifiers.sha384WithRSAEncryption)) {
            return "SHA-384";
        } else if (oid.equals(PKCSObjectIdentifiers.sha512WithRSAEncryption)) {
            return "SHA-512";
        } else if (oid.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption)) {
            return "SHA-1";
        }else {
            // 添加其他算法支持...
            throw new UnsupportedOperationException(algId.toString());
        }
    }
}
