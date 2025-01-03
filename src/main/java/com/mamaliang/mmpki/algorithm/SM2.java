package com.mamaliang.mmpki.algorithm;

import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;

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

    /**
     * Q = d 点乘 G
     * d  是私钥，一个大整数
     * G  是椭圆曲线上的生成点
     * Q  是椭圆曲线上的一个点，即公钥
     */
    public static ECPoint calculateQ(byte[] d) {
        ECParameterSpec sm2p256v1 = ECNamedCurveTable.getParameterSpec(GMObjectIdentifiers.sm2p256v1.getId());
        BigInteger privateKeyD = new BigInteger(1, d);
        ECPoint publicKeyQ = sm2p256v1.getG().multiply(privateKeyD);
        // 确保公钥是非压缩形式,即04开头
        return publicKeyQ.normalize();
    }

    /**
     * 将d转换成私钥对象
     */
    public static BCECPrivateKey convert2PrivateKey(byte[] d) throws NoSuchAlgorithmException, InvalidKeySpecException {
        ECParameterSpec sm2p256v1 = ECNamedCurveTable.getParameterSpec(GMObjectIdentifiers.sm2p256v1.getId());
        ECDomainParameters ecDomainParameters = new ECDomainParameters(sm2p256v1.getCurve(), sm2p256v1.getG(), sm2p256v1.getN());
        ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(new BigInteger(1, d), ecDomainParameters);
        // 计算公钥
        ECPoint Q = calculateQ(d);
        BCECPublicKey publicKey = convert2PublicKey(Q);
        return new BCECPrivateKey(ALGORITHM, ecPrivateKeyParameters, publicKey, sm2p256v1, BouncyCastleProvider.CONFIGURATION);

    }

    /**
     * X,Y 32/64位都可以,且都是正数
     */
    public static BCECPublicKey convert2PublicKey(byte[] x, byte[] y) throws NoSuchAlgorithmException, InvalidKeySpecException {
        ECParameterSpec sm2p256v1 = ECNamedCurveTable.getParameterSpec(GMObjectIdentifiers.sm2p256v1.getId());
        ECCurve sm2Curve = sm2p256v1.getCurve();
        ECPoint Q = sm2Curve.createPoint(new BigInteger(1, x), new BigInteger(1, y));
        return convert2PublicKey(Q);
    }

    public static BCECPublicKey convert2PublicKey(ECPoint Q) throws NoSuchAlgorithmException, InvalidKeySpecException {
        ECParameterSpec sm2p256v1 = ECNamedCurveTable.getParameterSpec(GMObjectIdentifiers.sm2p256v1.getId());
        ECPublicKeySpec sm2PubKeySpec = new ECPublicKeySpec(Q, sm2p256v1);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM, new BouncyCastleProvider());
        return (BCECPublicKey) keyFactory.generatePublic(sm2PubKeySpec);
    }

    public static byte[] encrypt(BCECPublicKey publicKey, byte[] plainText) throws InvalidCipherTextException {
        ECParameterSpec sm2p256v1 = ECNamedCurveTable.getParameterSpec(GMObjectIdentifiers.sm2p256v1.getId());
        ECDomainParameters ecDomainParameters = new ECDomainParameters(sm2p256v1.getCurve(), sm2p256v1.getG(), sm2p256v1.getN());
        ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(publicKey.getQ(), ecDomainParameters);
        SM2Engine sm2Engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        sm2Engine.init(true, new ParametersWithRandom(ecPublicKeyParameters, new SecureRandom()));
        return sm2Engine.processBlock(plainText, 0, plainText.length);
    }

    public static byte[] decrypt(BCECPrivateKey privateKey, byte[] encryptData) throws InvalidCipherTextException {
        if (encryptData[0] != 0x04) {
            throw new IllegalArgumentException("C1 of cipher may be compressed");
        }
        ECParameterSpec sm2p256v1 = ECNamedCurveTable.getParameterSpec(GMObjectIdentifiers.sm2p256v1.getId());
        ECDomainParameters domainParameters = new ECDomainParameters(sm2p256v1.getCurve(), sm2p256v1.getG(), sm2p256v1.getN());
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
