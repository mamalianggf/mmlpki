package com.mamaliang.mmpki.algorithm;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

/**
 * 当前只支持 secp256r1 曲线
 *
 * @author gaof
 * @date 2023/11/17
 */
public class ECC {

    public static final String CURVE_NAME = "secp256r1";

    public static final String SIGNATURE_SHA256_WITH_ECDSA = "SHA256withECDSA";

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        ECGenParameterSpec sm2Spec = new ECGenParameterSpec(CURVE_NAME);
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        keyPairGenerator.initialize(sm2Spec, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

}
