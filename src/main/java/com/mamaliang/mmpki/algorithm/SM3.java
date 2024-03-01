package com.mamaliang.mmpki.algorithm;

import org.bouncycastle.crypto.digests.SM3Digest;

/**
 * @author gaof
 * @date 2024/3/2
 */
public class SM3 {

    /**
     * 返回的hash值长度为32
     */
    public static byte[] hash(byte[] srcData) {
        SM3Digest digest = new SM3Digest();
        digest.update(srcData, 0, srcData.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return hash;
    }
}
