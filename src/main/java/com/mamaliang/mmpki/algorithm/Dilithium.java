package com.mamaliang.mmpki.algorithm;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * @author gaof
 * @date 2024/7/26
 */
public class Dilithium {

    public static final String ALGORITHM = "Dilithium";

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator dilKpGen = KeyPairGenerator.getInstance(ALGORITHM, new BouncyCastlePQCProvider());
        dilKpGen.initialize(DilithiumParameterSpec.dilithium3);
        return dilKpGen.generateKeyPair();
    }
}
