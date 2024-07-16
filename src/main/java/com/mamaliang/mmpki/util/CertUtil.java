package com.mamaliang.mmpki.util;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 * @author gaof
 * @date 2023/10/31
 */
public class CertUtil {

    public static Certificate selfIssueCert(boolean isCa, boolean isSig, boolean isEnc, String country, String stateOrProvince, String locality, String organization, String organizationUnit, String commonName, Date notBefore, Date notAfter, List<String> subjectAltNames, KeyPair keyPair, String signatureAlgorithm) throws OperatorCreationException, IOException, NoSuchAlgorithmException {
        X500Name dn = generateX500Name(country, stateOrProvince, locality, organization, organizationUnit, commonName);
        Extension bc = generateBasicConstraintsExt(isCa);
        Extension keyUsage = generateKeyUsageExt(isCa, isSig, isEnc);
        Extension sans = generateSANExt(subjectAltNames);
        Extension kp = generateExtKeyUsageExt();
        Extension ski = generateSubjectKeyIdentifierExt(keyPair.getPublic());
        Extension aki = generateAuthorityKeyIdentifierExt(keyPair.getPublic());
        List<Extension> exts = Arrays.asList(bc, keyUsage, sans, kp, ski, aki);
        return issueCert(dn, keyPair.getPublic(), notBefore, notAfter, exts, dn, keyPair.getPrivate(), signatureAlgorithm);
    }

    public static Certificate selfIssueCert(boolean isCa, boolean isSig, boolean isEnc, X500Name dn, Date notBefore, Date notAfter, List<String> subjectAltNames, KeyPair keyPair, String signatureAlgorithm) throws OperatorCreationException, IOException, NoSuchAlgorithmException {
        Extension bc = generateBasicConstraintsExt(isCa);
        Extension keyUsage = generateKeyUsageExt(isCa, isSig, isEnc);
        Extension sans = generateSANExt(subjectAltNames);
        Extension kp = generateExtKeyUsageExt();
        Extension ski = generateSubjectKeyIdentifierExt(keyPair.getPublic());
        Extension aki = generateAuthorityKeyIdentifierExt(keyPair.getPublic());
        List<Extension> exts = Arrays.asList(bc, keyUsage, sans, kp, ski, aki);
        return issueCert(dn, keyPair.getPublic(), notBefore, notAfter, exts, dn, keyPair.getPrivate(), signatureAlgorithm);
    }

    public static Certificate caIssueCert(boolean isCa, boolean isSig, boolean isEnc, String country, String stateOrProvince, String locality, String organization, String organizationUnit, String commonName, PublicKey subjectPublicKey, Date notBefore, Date notAfter, X500Name issuerDn, Extension sans, PublicKey issuerPublicKey, PrivateKey issuerPrivateKey, String signatureAlgorithm) throws OperatorCreationException, IOException, NoSuchAlgorithmException {
        X500Name subjectDn = generateX500Name(country, stateOrProvince, locality, organization, organizationUnit, commonName);
        Extension bc = generateBasicConstraintsExt(isCa);
        Extension keyUsage = generateKeyUsageExt(isCa, isSig, isEnc);
        Extension kp = generateExtKeyUsageExt();
        Extension ski = generateSubjectKeyIdentifierExt(subjectPublicKey);
        Extension aki = generateAuthorityKeyIdentifierExt(issuerPublicKey);
        List<Extension> exts = Arrays.asList(bc, keyUsage, sans, kp, ski, aki);
        return issueCert(subjectDn, subjectPublicKey, notBefore, notAfter, exts, issuerDn, issuerPrivateKey, signatureAlgorithm);
    }

    public static Certificate caIssueCert(boolean isCa, boolean isSig, boolean isEnc, X500Name subjectDn, PublicKey subjectPublicKey, Date notBefore, Date notAfter, X500Name issuerDn, Extension sans, PublicKey issuerPublicKey, PrivateKey issuerPrivateKey, String signatureAlgorithm) throws OperatorCreationException, IOException, NoSuchAlgorithmException {
        Extension bc = generateBasicConstraintsExt(isCa);
        Extension keyUsage = generateKeyUsageExt(isCa, isSig, isEnc);
        Extension kp = generateExtKeyUsageExt();
        Extension ski = generateSubjectKeyIdentifierExt(subjectPublicKey);
        Extension aki = generateAuthorityKeyIdentifierExt(issuerPublicKey);
        List<Extension> exts = new ArrayList<>(Arrays.asList(bc, keyUsage, kp, ski, aki));
        if (!Objects.isNull(sans)) {
            exts.add(sans);
        }
        return issueCert(subjectDn, subjectPublicKey, notBefore, notAfter, exts, issuerDn, issuerPrivateKey, signatureAlgorithm);
    }

    public static PublicKey extraPublicKey(Certificate cert) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        SubjectPublicKeyInfo subjectPublicKeyInfo = cert.getSubjectPublicKeyInfo();
        String algo = subjectPublicKeyInfo.getAlgorithm().getAlgorithm().getId();
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance(algo, new BouncyCastleProvider());
        return keyFactory.generatePublic(x509EncodedKeySpec);
    }

    private static Certificate issueCert(X500Name subjectDn, PublicKey subjectPublicKey, Date notBefore, Date notAfter, List<Extension> extensions, X500Name issuerDn, PrivateKey issuerPrivateKey, String signatureAlgorithm) throws OperatorCreationException, CertIOException {

        // subject serial
        BigInteger serial = generateSerial();

        // content sign function
        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(new BouncyCastleProvider())
                .build(issuerPrivateKey);

        // add ext
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerDn, serial, notBefore, notAfter, subjectDn, subjectPublicKey);
        for (Extension extension : extensions) {
            builder.addExtension(extension);
        }

        return builder.build(contentSigner).toASN1Structure();

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

    private static BigInteger generateSerial() {
        return BigInteger.probablePrime(128, new Random());
    }

    private static Extension generateBasicConstraintsExt(boolean isCa) throws IOException {
        return Extension.create(Extension.basicConstraints, true, new BasicConstraints(isCa));
    }

    private static Extension generateKeyUsageExt(boolean isCa, boolean isSig, boolean isEnc) throws IOException {
        KeyUsage keyUsage;
        if (isCa) {
            keyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        } else if (isSig & isEnc) {
            keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.nonRepudiation);
        } else if (isSig) {
            keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation);
        } else if (isEnc) {
            keyUsage = new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.dataEncipherment);
        } else {
            keyUsage = new KeyUsage(KeyUsage.nonRepudiation);
        }
        return Extension.create(Extension.keyUsage, true, keyUsage);
    }

    public static Extension generateSANExt(List<String> subjectAltNames) throws IOException {
        GeneralName[] sans = new GeneralName[subjectAltNames.size()];
        String ipRegex = "(((\\d{1,2})|(1\\d{2})|(2[0-4]\\d)|(25[0-5]))\\.){3}((\\d{1,2})|(1\\d{2})|(2[0-4]\\d)|(25[0-5]))";
        for (int i = 0; i < subjectAltNames.size(); i++) {
            if (subjectAltNames.get(i).matches(ipRegex)) {
                sans[i] = new GeneralName(GeneralName.iPAddress, subjectAltNames.get(i));
            } else {
                sans[i] = new GeneralName(GeneralName.dNSName, subjectAltNames.get(i));
            }
        }
        return Extension.create(Extension.subjectAlternativeName, false, new GeneralNames(sans));
    }

    private static Extension generateExtKeyUsageExt() throws IOException {
        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth});
        return Extension.create(Extension.extendedKeyUsage, true, extendedKeyUsage);
    }

    private static Extension generateAuthorityKeyIdentifierExt(PublicKey issuerPublicKey) throws IOException, NoSuchAlgorithmException {
        JcaX509ExtensionUtils jcaX509ExtensionUtils = new JcaX509ExtensionUtils();
        AuthorityKeyIdentifier authorityKeyIdentifier = jcaX509ExtensionUtils.createAuthorityKeyIdentifier(issuerPublicKey);
        return Extension.create(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);
    }

    private static Extension generateSubjectKeyIdentifierExt(PublicKey subjectPublicKey) throws IOException, NoSuchAlgorithmException {
        JcaX509ExtensionUtils jcaX509ExtensionUtils = new JcaX509ExtensionUtils();
        SubjectKeyIdentifier subjectKeyIdentifier = jcaX509ExtensionUtils.createSubjectKeyIdentifier(subjectPublicKey);
        return Extension.create(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
    }
}
