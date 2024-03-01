package com.mamaliang.mmpki.algorithm;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * @author gaof
 * @date 2023/11/8
 */
public class RSA {

    public static final String ALGORITHM = "RSA";

    public static final int DEFAULT_KEY_SIZE = 2048;

    public static final String SIGNATURE_SHA256_WITH_RSA = "SHA256withRSA";

    public static KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerate = KeyPairGenerator.getInstance(ALGORITHM, new BouncyCastleProvider());
        SecureRandom secureRandom = new SecureRandom();
        keyPairGenerate.initialize(keySize, secureRandom);
        return keyPairGenerate.generateKeyPair();
    }

}
