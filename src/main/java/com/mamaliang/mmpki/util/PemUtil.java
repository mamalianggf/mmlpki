package com.mamaliang.mmpki.util;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * @author gaof
 * @date 2023/10/30
 */
public class PemUtil {

    public static String csr2pem(PKCS10CertificationRequest pkcs10CertificationRequest) throws IOException {
        return object2pem(PEMParser.TYPE_CERTIFICATE_REQUEST, pkcs10CertificationRequest.getEncoded());
    }

    public static String cert2pem(Certificate cert) throws IOException {
        return object2pem(PEMParser.TYPE_CERTIFICATE, cert.getEncoded());
    }

    public static String privateKey2pem(PrivateKey privateKey) throws IOException {
        return object2pem(PEMParser.TYPE_PRIVATE_KEY, privateKey.getEncoded());
    }

    private static String object2pem(String type, byte[] encode) throws IOException {
        try (StringWriter stringWriter = new StringWriter();
             PemWriter pemWriter = new PemWriter(stringWriter)) {
            PemObject pemObject = new PemObject(type, encode);
            pemWriter.writeObject(pemObject);
            pemWriter.flush();
            return stringWriter.toString();
        }
    }

    public static PKCS10CertificationRequest pem2CSR(String pem) throws IOException {
        try (StringReader stringReader = new StringReader(pem);
             PEMParser pemParser = new PEMParser(stringReader)) {
            return (PKCS10CertificationRequest) pemParser.readObject();
        }
    }

    public static Certificate pem2Cert(String pem) throws IOException {
        try (StringReader stringReader = new StringReader(pem);
             PEMParser pemParser = new PEMParser(stringReader)) {
            X509CertificateHolder holder = (X509CertificateHolder) pemParser.readObject();
            return holder.toASN1Structure();
        }
    }

    public static PrivateKey pem2privateKey(String pem) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        try (StringReader stringReader = new StringReader(pem);
             PEMParser pemParser = new PEMParser(stringReader)) {
            PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) pemParser.readObject();
            String algo = privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm().getId();
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance(algo, new BouncyCastleProvider());
            return keyFactory.generatePrivate(keySpec);
        }
    }


}
