package com.mamaliang.mmpki.algorithm;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

/**
 * {@link GMObjectIdentifiers}
 *
 * @author gaof
 * @date 2023/10/31
 */
public class SM2 {

    public static final String ALGORITHM = "EC";

    public static final String CURVE_NAME = "sm2p256v1";

    public static final String SIGNATURE_SM3_WITH_SM2 = "SM3withSM2";

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        ECGenParameterSpec sm2Spec = new ECGenParameterSpec(CURVE_NAME);
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM, new BouncyCastleProvider());
        keyPairGenerator.initialize(sm2Spec, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

    public static BCECPrivateKey convert2PrivateKey(byte[] d) {
        X9ECParameters sm2ECParameters = GMNamedCurves.getByName(CURVE_NAME);
        ECDomainParameters ecDomainParameters = new ECDomainParameters(sm2ECParameters.getCurve(), sm2ECParameters.getG(), sm2ECParameters.getN());
        ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(new BigInteger(1, d), ecDomainParameters);
        return new BCECPrivateKey(ALGORITHM, ecPrivateKeyParameters, BouncyCastleProvider.CONFIGURATION);
    }

    /**
     * X,Y 32/64位都可以,且都是正数
     */
    public static BCECPublicKey convert2PublicKey(byte[] x, byte[] y) {
        X9ECParameters sm2ECParameters = GMNamedCurves.getByName(CURVE_NAME);
        ECDomainParameters ecDomainParameters = new ECDomainParameters(sm2ECParameters.getCurve(), sm2ECParameters.getG(), sm2ECParameters.getN());
        ECPoint point = sm2ECParameters.getCurve().createPoint(new BigInteger(x), new BigInteger(y));
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(point, ecDomainParameters);
        return new BCECPublicKey(ALGORITHM, ecPublicKeyParameters, BouncyCastleProvider.CONFIGURATION);
    }

    public static byte[] encrypt(BCECPublicKey publicKey, byte[] plainText) throws InvalidCipherTextException {
        X9ECParameters sm2ECParameters = GMNamedCurves.getByName(CURVE_NAME);
        ECDomainParameters ecDomainParameters = new ECDomainParameters(sm2ECParameters.getCurve(), sm2ECParameters.getG(), sm2ECParameters.getN());
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(publicKey.getQ(), ecDomainParameters);
        SM2Engine sm2Engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        sm2Engine.init(true, new ParametersWithRandom(ecPublicKeyParameters, new SecureRandom()));
        return sm2Engine.processBlock(plainText, 0, plainText.length);
    }

    public static byte[] decrypt(BCECPrivateKey privateKey, byte[] encryptData) throws InvalidCipherTextException {
        if (encryptData[0] != 0x04) {
            throw new IllegalArgumentException("C1 of cipher may be compressed");
        }
        X9ECParameters sm2ECParameters = GMNamedCurves.getByName(CURVE_NAME);
        ECDomainParameters domainParameters = new ECDomainParameters(sm2ECParameters.getCurve(), sm2ECParameters.getG(), sm2ECParameters.getN());
        ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(privateKey.getD(), domainParameters);
        SM2Engine sm2Engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        sm2Engine.init(false, privateKeyParameters);
        return sm2Engine.processBlock(encryptData, 0, encryptData.length);
    }

    public static byte[] sign(BCECPrivateKey privateKey, byte[] plainText) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), new BouncyCastleProvider());
        signature.initSign(privateKey);
        signature.update(plainText);
        return signature.sign();
    }

    public static boolean verify(BCECPublicKey publicKey, byte[] plainText, byte[] signatureText) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), new BouncyCastleProvider());
        signature.initVerify(publicKey);
        signature.update(plainText);
        return signature.verify(signatureText);
    }
}
