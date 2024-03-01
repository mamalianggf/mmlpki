package com.mamaliang.mmpki.nsag;

import com.mamaliang.mmpki.algorithm.SM2;
import com.mamaliang.mmpki.util.PemUtil;
import org.junit.jupiter.api.Test;

import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

/**
 * @author gaof
 * @date 2024/1/17
 */
public class KeyTest {

    @Test
    void sm2() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        KeyPair keyPair = SM2.generateKeyPair();
        String privateKeyPem = PemUtil.privateKey2pem(keyPair.getPrivate());
        String publicKeyPem = PemUtil.publicKey2pem(keyPair.getPublic());

        try (FileWriter pri = new FileWriter("/Users/mamaliang/Downloads/sm2Private.pem");
             FileWriter pub = new FileWriter("/Users/mamaliang/Downloads/sm2Public.key")) {
            pri.write(privateKeyPem);
            pub.write(publicKeyPem);
        }
    }
}
