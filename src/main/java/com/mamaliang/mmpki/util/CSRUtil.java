package com.mamaliang.mmpki.util;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

/**
 * @author gaof
 * @date 2023/11/16
 */
public class CSRUtil {

    public static PKCS10CertificationRequest generateCSR(String country, String stateOrProvince, String locality, String organization, String organizationUnit, String commonName, List<String> subjectAltNames, KeyPair keyPair, String signatureAlgorithm) throws OperatorCreationException, IOException {

        // 主体信息
        X500Name dn = generateX500Name(country, stateOrProvince, locality, organization, organizationUnit, commonName);

        return generateCSR(dn, subjectAltNames, keyPair, signatureAlgorithm);
    }

    public static PKCS10CertificationRequest generateCSR(X500Name dn, List<String> subjectAltNames, KeyPair keyPair, String signatureAlgorithm) throws OperatorCreationException, IOException {

        // 添加主体备用名
        GeneralNames sans = generateSAN(subjectAltNames);

        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.subjectAlternativeName, true, sans);

        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(new BouncyCastleProvider())
                .build(keyPair.getPrivate());

        return new JcaPKCS10CertificationRequestBuilder(dn, keyPair.getPublic())
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate())
                .build(contentSigner);
    }

    public static PublicKey extraPublicKey(PKCS10CertificationRequest csr) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        SubjectPublicKeyInfo subjectPublicKeyInfo = csr.getSubjectPublicKeyInfo();
        String algo = subjectPublicKeyInfo.getAlgorithm().getAlgorithm().getId();
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance(algo, new BouncyCastleProvider());
        return keyFactory.generatePublic(x509EncodedKeySpec);
    }

    private static X500Name generateX500Name(String country, String stateOrProvince, String locality, String organization, String organizationUnit, String commonName) {
        return new X500NameBuilder()
                .addRDN(BCStyle.C, country)
                .addRDN(BCStyle.ST, stateOrProvince)
                .addRDN(BCStyle.L, locality)
                .addRDN(BCStyle.O, organization)
                .addRDN(BCStyle.OU, organizationUnit)
                .addRDN(BCStyle.CN, commonName)
                .build();
    }

    private static GeneralNames generateSAN(List<String> subjectAltNames) {
        GeneralName[] sans = new GeneralName[subjectAltNames.size()];
        String ipRegex = "(((\\d{1,2})|(1\\d{2})|(2[0-4]\\d)|(25[0-5]))\\.){3}((\\d{1,2})|(1\\d{2})|(2[0-4]\\d)|(25[0-5]))";
        for (int i = 0; i < subjectAltNames.size(); i++) {
            if (subjectAltNames.get(i).matches(ipRegex)) {
                sans[i] = new GeneralName(GeneralName.iPAddress, subjectAltNames.get(i));
            } else {
                sans[i] = new GeneralName(GeneralName.dNSName, subjectAltNames.get(i));
            }
        }
        return new GeneralNames(sans);
    }

}
