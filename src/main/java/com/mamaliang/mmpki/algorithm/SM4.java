package com.mamaliang.mmpki.algorithm;

import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * {@link GMObjectIdentifiers}
 *
 * @author gaof
 * @date 2023/10/31
 */
public class SM4 {

    public static final String ALGORITHM = "SM4";

    public static final String SM4_ECB_NOPADDING = "SM4/ECB/NoPadding";

    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM, new BouncyCastleProvider());
        return keyGenerator.generateKey();
    }

    public static byte[] ecbEncrypt(SecretKey key, byte[] plainData) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(SM4_ECB_NOPADDING, new BouncyCastleProvider());
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plainData);
    }

    public static byte[] ecbDecrypt(SecretKey key, byte[] encryptedData) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(SM4_ECB_NOPADDING, new BouncyCastleProvider());
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedData);
    }

}
