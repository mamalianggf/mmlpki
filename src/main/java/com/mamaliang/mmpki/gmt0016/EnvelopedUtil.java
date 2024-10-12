package com.mamaliang.mmpki.gmt0016;

import com.mamaliang.mmpki.algorithm.AlgorithmID;
import com.mamaliang.mmpki.algorithm.SM1;
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
import java.security.spec.InvalidKeySpecException;
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
     * @param eccEnvelopedKeyBlob   信封
     * @param signPrivateKey        签名私钥
     * @param dynamicLibName        用于SM1,当使用
     * @param existEccContainerName 用于SM1
     * @return 加密私钥
     */
    public static BCECPrivateKey disassemble(SKF_ENVELOPEDKEYBLOB eccEnvelopedKeyBlob, BCECPrivateKey signPrivateKey, String dynamicLibName, String existEccContainerName) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidCipherTextException {
        // 组装非对称密文
        byte[] encryptData = constructEncryptData(eccEnvelopedKeyBlob);
        // 依靠签名私钥解出对称密钥
        byte[] symmKey = SM2.decrypt(signPrivateKey, encryptData);

        // 由于加密私钥的d是32位,且由组装时扩充到64位所以,这里需要移除前面所有的0
        byte[] tempCbEncryptedPrivKey = new byte[32];
        System.arraycopy(eccEnvelopedKeyBlob.cbEncryptedPrivKey, 32, tempCbEncryptedPrivKey, 0, 32);

        byte[] encPrivateKeyBytes;

        int ulSymmAlgId = eccEnvelopedKeyBlob.ulSymmAlgId;
        if (AlgorithmID.SGD_SM1_ECB == ulSymmAlgId) {
            // SM1没有软件实现，需要使用硬件解密
            encPrivateKeyBytes = SM1.ecbDecrypt(dynamicLibName, existEccContainerName, symmKey, tempCbEncryptedPrivKey);
        } else if (AlgorithmID.SGD_SM4_ECB == ulSymmAlgId) {
            // 依靠SM4对称密码解出加密私钥
            SecretKey key = new SecretKeySpec(symmKey, "SM4");
            encPrivateKeyBytes = SM4.ecbDecrypt(key, tempCbEncryptedPrivKey);
        } else {
            throw new UnsupportedOperationException("规范中只约定了SM1和SM4");
        }
        return SM2.convert2PrivateKey(encPrivateKeyBytes);
    }

    /**
     * 封装信封
     *
     * @param encPrivateKey 加密证书私钥
     * @param encPublicKey  加密证书公钥
     * @param signPublicKey 签名证书公钥
     * @return 信封
     */
    public static SKF_ENVELOPEDKEYBLOB assemble(BCECPrivateKey encPrivateKey, BCECPublicKey encPublicKey, BCECPublicKey signPublicKey) throws Exception {
        // 加密私钥中提取 d
        BigInteger d = encPrivateKey.getD();
        byte[] dBytes = d.toByteArray();
        if (dBytes[0] == 0x00) {// d一定是正数
            dBytes = deleteTheFirstByte(dBytes);
        }
        // 对称密钥 加密 d
        SecretKey symmKey = SM4.generateKey();
        byte[] cbEncryptedPrivKey = SM4.ecbEncrypt(symmKey, dBytes);
        // 不足64bit,补全至64bit
        cbEncryptedPrivKey = completeByteArray(cbEncryptedPrivKey, 64);
        // 签名公钥加密加密私钥
        byte[] symmKeyBytes = symmKey.getEncoded();
        byte[] encryptedSymmKeyBytes = SM2.encrypt(signPublicKey, symmKeyBytes);

        byte[] x = encPublicKey.getQ().getAffineXCoord().getEncoded();
        x = completeByteArray(x, 64);
        byte[] y = encPublicKey.getQ().getAffineYCoord().getEncoded();
        y = completeByteArray(y, 64);
        Struct_ECCPUBLICKEYBLOB eccPublicKeyBlob = new Struct_ECCPUBLICKEYBLOB(256, x, y);

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
        c1x = completeByteArray(c1x, 64);
        c1y = completeByteArray(c1y, 64);
        Struct_ECCCIPHERBLOB eccCipherBlob = new Struct_ECCCIPHERBLOB(c1x, c1y, c3, c2.length, c2);

        return new SKF_ENVELOPEDKEYBLOB(SKF_ENVELOPEDKEYBLOB.VERSION, AlgorithmID.SGD_SM4_ECB, 256, cbEncryptedPrivKey, eccPublicKeyBlob, eccCipherBlob);
    }

    public static String convertAnXinCa0010(SignedAndEnvelopedData signedAndEnvelopedData, BCECPublicKey bcecPublicKey) {
        RecipientInfo recipientInfo = RecipientInfo.getInstance(signedAndEnvelopedData.getRecipientInfos().getObjectAt(0));
        ASN1Encodable asn1Encodable = recipientInfo.getInfo();
        Struct_ECCCIPHERBLOB eccCipherBlob;
        if (asn1Encodable instanceof KeyTransRecipientInfo keyTransRecipientInfo) {
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
            x = completeByteArray(x, 64);
            y = completeByteArray(y, 64);
            eccCipherBlob = new Struct_ECCCIPHERBLOB(x, y, hash, cipher.length, cipher);
        } else {
            throw new IllegalArgumentException("RecipientInfo not KeyTransRecipientInfo");
        }
        // 对称密钥加密的加密私钥
        ASN1OctetString encryptedContent = signedAndEnvelopedData.getEncryptedContentInfo().getEncryptedContent();
        byte[] encryptedPrivateKey = encryptedContent.getOctets();

        ECPoint q = bcecPublicKey.getQ();
        byte[] x = q.getXCoord().getEncoded();
        byte[] y = q.getYCoord().getEncoded();
        x = completeByteArray(x, 64);
        y = completeByteArray(y, 64);
        Struct_ECCPUBLICKEYBLOB eccPublicKeyBlob = new Struct_ECCPUBLICKEYBLOB(256, x, y);

        SKF_ENVELOPEDKEYBLOB eccEnvelopedKeyBlob = new SKF_ENVELOPEDKEYBLOB(SKF_ENVELOPEDKEYBLOB.VERSION, AlgorithmID.SGD_SM4_ECB, 256, encryptedPrivateKey, eccPublicKeyBlob, eccCipherBlob);
        return new String(Base64.getEncoder().encode(SKF_ENVELOPEDKEYBLOB.encode(eccEnvelopedKeyBlob)), StandardCharsets.UTF_8);
    }

    public static String convert0009(SM2EnvelopedKey sm2EnvelopedKey) {
        SM2Cipher sm2Cipher = sm2EnvelopedKey.getSm2Cipher();
        byte[] x = sm2Cipher.getX().getValue().toByteArray();
        byte[] y = sm2Cipher.getY().getValue().toByteArray();
        byte[] hash = sm2Cipher.getHash().getOctets();
        byte[] cipher = sm2Cipher.getCipher().getOctets();
        x = completeByteArray(x, 64);
        y = completeByteArray(y, 64);
        Struct_ECCCIPHERBLOB eccCipherBlob = new Struct_ECCCIPHERBLOB(x, y, hash, cipher.length, cipher);

        // 对称密钥加密的加密私钥
        byte[] encryptedPrivateKey = sm2EnvelopedKey.getSm2EncryptedPrivateKey().getOctets();
        // 不足64bit,补全至64bit
        encryptedPrivateKey = completeByteArray(encryptedPrivateKey, 64);

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
        qx = completeByteArray(qx, 64);
        qy = completeByteArray(qy, 64);
        Struct_ECCPUBLICKEYBLOB eccPublicKeyBlob = new Struct_ECCPUBLICKEYBLOB(256, qx, qy);

        SKF_ENVELOPEDKEYBLOB eccEnvelopedKeyBlob = new SKF_ENVELOPEDKEYBLOB(SKF_ENVELOPEDKEYBLOB.VERSION, AlgorithmID.SGD_SM4_ECB, 256, encryptedPrivateKey, eccPublicKeyBlob, eccCipherBlob);
        return new String(Base64.getEncoder().encode(SKF_ENVELOPEDKEYBLOB.encode(eccEnvelopedKeyBlob)), StandardCharsets.UTF_8);
    }


    private static byte[] constructEncryptData(SKF_ENVELOPEDKEYBLOB eccEnvelopedKeyBlob) {
        Struct_ECCCIPHERBLOB eccCipherBlob = eccEnvelopedKeyBlob.eccCipherBlob;
        byte[] x = eccCipherBlob.xCoordinate;
        byte[] tempX = new byte[32];
        System.arraycopy(x, 32, tempX, 0, 32);
        byte[] y = eccCipherBlob.yCoordinate;
        byte[] tempY = new byte[32];
        System.arraycopy(y, 32, tempY, 0, 32);
        byte[] c3 = eccCipherBlob.hash;
        byte[] c2 = eccCipherBlob.cipher;
        byte[] tempC2 = new byte[eccCipherBlob.cipherLen];
        System.arraycopy(c2, 0, tempC2, 0, eccCipherBlob.cipherLen);

        ByteBuffer bb = ByteBuffer.allocate(1 + tempX.length + tempY.length + c3.length + tempC2.length);
        byte notCompress = 0x04;
        bb.put(notCompress);
        bb.put(tempX);
        bb.put(tempY);
        bb.put(c3);
        bb.put(tempC2);
        return bb.array();
    }

    private static byte[] deleteTheFirstByte(byte[] bytes) {
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        bb.position(1);
        byte[] temp = new byte[bb.remaining()];
        bb.get(temp);
        return temp;
    }

    /**
     * 补全位数至goal,补前面
     */
    private static byte[] completeByteArray(byte[] bytes, int goal) {
        if (bytes.length < goal) {
            byte[] temp = new byte[goal];
            System.arraycopy(bytes, 0, temp, temp.length - bytes.length, bytes.length);
            return temp;
        }
        return bytes;
    }
}
