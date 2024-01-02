package com.mamaliang.mmpki.gmt0016;

import com.mamaliang.mmpki.algorithm.AlgorithmID;
import com.mamaliang.mmpki.algorithm.SM2;
import com.mamaliang.mmpki.algorithm.SM4;
import com.mamaliang.mmpki.gmt0009.SM2Cipher;
import com.mamaliang.mmpki.gmt0009.SM2EnvelopedKey;
import com.mamaliang.mmpki.gmt0010.SignedAndEnvelopedData;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * 0016-2012 SKF_ENVELOPEDKEYBLOB
 *
 * @author gaof
 * @date 2023/10/31
 */
public class EnvelopedUtil {


    /**
     * 解信封:从信封中提取加密私钥
     *
     * @param eccEnvelopedKeyBlobBase64 信封内容
     * @param signPrivateKey            签名私钥
     */
    public static BCECPrivateKey disassemble(String eccEnvelopedKeyBlobBase64, BCECPrivateKey signPrivateKey) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidCipherTextException {
        byte[] eccEnvelopedKeyBlobBytes = Base64.getDecoder().decode(eccEnvelopedKeyBlobBase64.getBytes(StandardCharsets.UTF_8));
        ECCEnvelopedKeyBlob eccEnvelopedKeyBlob = ECCEnvelopedKeyBlob.decode(eccEnvelopedKeyBlobBytes);

        // 组装密文
        byte[] encryptData = constructEncryptData(eccEnvelopedKeyBlob);

        // 依靠签名私钥解出对称密钥
        byte[] symmKey = SM2.decrypt(signPrivateKey, encryptData);

        // 依靠对称密码解出加密私钥
        SecretKey key = new SecretKeySpec(symmKey, "SM4");
        byte[] encPrivateKeyBytes = SM4.ecbDecrypt(key, symmKey);

        return SM2.generatePrivateKey(encPrivateKeyBytes);
    }

    /**
     * 封装信封
     *
     * @param encPrivateKey 加密证书私钥
     * @param encPublicKey  加密证书公钥
     * @param signPublicKey 签名证书公钥
     * @return 信封base64
     * @throws Exception
     */
    public static String assemble(BCECPrivateKey encPrivateKey, BCECPublicKey encPublicKey, BCECPublicKey signPublicKey) throws Exception {
        // 加密私钥中提取 d
        BigInteger d = encPrivateKey.getD();
        byte[] dBytes = d.toByteArray();
        if (dBytes[0] == 0x00) {
            dBytes = deleteTheFirstByte(dBytes);
        }
        // 对称密钥 加密 d
        SecretKey symmKey = SM4.generateKey();
        byte[] cbEncryptedPrivKey = SM4.ecbEncrypt(symmKey, dBytes);
        if (cbEncryptedPrivKey.length < 64) {
            // 不足64bit,补全至64bit
            byte[] temp = new byte[64];
            System.arraycopy(cbEncryptedPrivKey, 0, temp, temp.length - cbEncryptedPrivKey.length, cbEncryptedPrivKey.length);
            cbEncryptedPrivKey = temp;
        }

        // 签名公钥加密加密私钥
        byte[] symmKeyBytes = symmKey.getEncoded();
        byte[] encryptedSymmKeyBytes = SM2.encrypt(signPublicKey, symmKeyBytes);
        ECCPublicKeyBlob eccPublicKeyBlob = new ECCPublicKeyBlob(256, encPublicKey.getQ().getAffineXCoord().getEncoded(), encPublicKey.getQ().getAffineYCoord().getEncoded());

        if (encryptedSymmKeyBytes[0] == 0x04) {
            encryptedSymmKeyBytes = deleteTheFirstByte(encryptedSymmKeyBytes);
        }
        ByteBuffer bb = ByteBuffer.wrap(encryptedSymmKeyBytes);
        byte[] c1x = new byte[32];
        byte[] c1y = new byte[32];
        byte[] c3 = new byte[32];
        bb.get(c1x);
        bb.get(c1y);
        bb.get(c3);
        byte[] c2 = new byte[bb.remaining()];
        bb.get(c2);
        ECCCipherBlob eccCipherBlob = new ECCCipherBlob(c1x, c1y, c3, c2.length, c2);

        ECCEnvelopedKeyBlob eccEnvelopedKeyBlob = new ECCEnvelopedKeyBlob(ECCEnvelopedKeyBlob.VERSION, AlgorithmID.SGD_SM4_ECB, 256, cbEncryptedPrivKey, eccPublicKeyBlob, eccCipherBlob);

        return new String(Base64.getEncoder().encode(ECCEnvelopedKeyBlob.encode(eccEnvelopedKeyBlob)), StandardCharsets.UTF_8);
    }

    public static String convertAnXinCa0010(SignedAndEnvelopedData signedAndEnvelopedData, BCECPublicKey bcecPublicKey) {
        RecipientInfo recipientInfo = RecipientInfo.getInstance(signedAndEnvelopedData.getRecipientInfos().getObjectAt(0));
        ASN1Encodable asn1Encodable = recipientInfo.getInfo();
        ECCCipherBlob eccCipherBlob = null;
        if (asn1Encodable instanceof KeyTransRecipientInfo) {
            KeyTransRecipientInfo keyTransRecipientInfo = (KeyTransRecipientInfo) asn1Encodable;
            // 加密的对称密钥 SM2cipher
            ASN1OctetString encryptedKey = keyTransRecipientInfo.getEncryptedKey();
            SM2Cipher sm2Cipher = new SM2Cipher(ASN1Sequence.getInstance(encryptedKey.getOctets()));
            byte[] x = sm2Cipher.getX().getValue().toByteArray();
            if (x[0] == 0x00) {
                x = deleteTheFirstByte(x);
            }
            byte[] y = sm2Cipher.getY().getValue().toByteArray();
            if (y[0] == 0x00) {
                y = deleteTheFirstByte(y);
            }
            byte[] hash = sm2Cipher.getHash().getOctets();
            byte[] cipher = sm2Cipher.getCipher().getOctets();
            eccCipherBlob = new ECCCipherBlob(x, y, hash, cipher.length, cipher);
        } else {
            throw new IllegalArgumentException("RecipientInfo not KeyTransRecipientInfo");
        }
        // 对称密钥加密的加密私钥
        ASN1OctetString encryptedContent = signedAndEnvelopedData.getEncryptedContentInfo().getEncryptedContent();
        byte[] encryptedPrivateKey = encryptedContent.getOctets();

        ECPoint q = bcecPublicKey.getQ();
        byte[] x = q.getXCoord().getEncoded();
        byte[] y = q.getYCoord().getEncoded();
        ECCPublicKeyBlob eccPublicKeyBlob = new ECCPublicKeyBlob(256, x, y);

        ECCEnvelopedKeyBlob eccEnvelopedKeyBlob = new ECCEnvelopedKeyBlob(ECCEnvelopedKeyBlob.VERSION, AlgorithmID.SGD_SM4_ECB, 256, encryptedPrivateKey, eccPublicKeyBlob, eccCipherBlob);
        return new String(Base64.getEncoder().encode(ECCEnvelopedKeyBlob.encode(eccEnvelopedKeyBlob)), StandardCharsets.UTF_8);
    }

    public static String convert0009(SM2EnvelopedKey sm2EnvelopedKey) {
        SM2Cipher sm2Cipher = sm2EnvelopedKey.getSm2Cipher();
        byte[] x = sm2Cipher.getX().getValue().toByteArray();
        byte[] y = sm2Cipher.getY().getValue().toByteArray();
        byte[] hash = sm2Cipher.getHash().getOctets();
        byte[] cipher = sm2Cipher.getCipher().getOctets();
        ECCCipherBlob eccCipherBlob = new ECCCipherBlob(x, y, hash, cipher.length, cipher);

        // 对称密钥加密的加密私钥
        byte[] encryptedPrivateKey = sm2EnvelopedKey.getSm2EncryptedPrivateKey().getOctets();
        if (encryptedPrivateKey.length < 64) {
            // 不足64bit,补全至64bit
            byte[] temp = new byte[64];
            System.arraycopy(encryptedPrivateKey, 0, temp, temp.length - encryptedPrivateKey.length, encryptedPrivateKey.length);
            encryptedPrivateKey = temp;
        }

        byte[] sm2PublicKey = sm2EnvelopedKey.getSm2PublicKey().getOctets();
        if (sm2PublicKey.length != 65) {
            throw new IllegalArgumentException("sm2PublicKey's length should be 65");
        }
        if (sm2PublicKey[0] != 0x04) {
            throw new IllegalArgumentException("sm2PublicKey's should not compress");
        }
        byte[] qx = new byte[32];
        byte[] qy = new byte[32];
        System.arraycopy(sm2PublicKey, 1, qx, 0, 32);
        System.arraycopy(sm2PublicKey, 33, qy, 0, 32);
        ECCPublicKeyBlob eccPublicKeyBlob = new ECCPublicKeyBlob(256, qx, qy);

        ECCEnvelopedKeyBlob eccEnvelopedKeyBlob = new ECCEnvelopedKeyBlob(ECCEnvelopedKeyBlob.VERSION, AlgorithmID.SGD_SM4_ECB, 256, encryptedPrivateKey, eccPublicKeyBlob, eccCipherBlob);
        return new String(Base64.getEncoder().encode(ECCEnvelopedKeyBlob.encode(eccEnvelopedKeyBlob)), StandardCharsets.UTF_8);
    }


    private static byte[] constructEncryptData(ECCEnvelopedKeyBlob eccEnvelopedKeyBlob) {
        ECCCipherBlob eccCipherBlob = eccEnvelopedKeyBlob.getEccCipherBlob();
        byte[] x = eccCipherBlob.getxCoordinate();
        byte[] y = eccCipherBlob.getyCoordinate();
        byte[] c3 = eccCipherBlob.getHash();
        byte[] c2 = eccCipherBlob.getCipher();

        ByteBuffer bb = ByteBuffer.allocate(1 + x.length + y.length + c3.length + c2.length);
        byte notCompress = 0x04;
        bb.put(notCompress);
        bb.put(x);
        bb.put(y);
        bb.put(c3);
        bb.put(c2);
        return bb.array();
    }

    private static byte[] deleteTheFirstByte(byte[] bytes) {
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        bb.position(1);
        byte[] temp = new byte[bb.remaining()];
        bb.get(temp);
        return temp;
    }

}
