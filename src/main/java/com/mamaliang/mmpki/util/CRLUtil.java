package com.mamaliang.mmpki.util;

import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * @author gaof
 * @date 2023/11/29
 */
public class CRLUtil {

    public static X509CRL createCRL(X509Certificate caCert, PrivateKey caKey, String sigAlg) throws IOException, GeneralSecurityException, OperatorCreationException {
        X509v2CRLBuilder crlBuilder = new JcaX509v2CRLBuilder(caCert.getSubjectX500Principal(), calculateDate(0));

        crlBuilder.setNextUpdate(calculateDate(7 * 24));
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        crlBuilder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert.getPublicKey()));

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider(new BouncyCastleProvider()).build(caKey);

        X509CRLHolder crlHolder = crlBuilder.build(signer);

        JcaX509CRLConverter converter = new JcaX509CRLConverter().setProvider(new BouncyCastleProvider());
        return converter.getCRL(crlHolder);
    }

    public static X509CRL addRevocationToCRL(PrivateKey caKey, String sigAlg, X509CRL crl, X509Certificate certToRevoke) throws GeneralSecurityException, OperatorCreationException {
        JcaX509v2CRLBuilder crlBuilder = new JcaX509v2CRLBuilder(crl);
        crlBuilder.setNextUpdate(calculateDate(7 * 24));

        // 吊销原因默认为私钥泄露
        crlBuilder.addCRLEntry(certToRevoke.getSerialNumber(), new Date(), CRLReason.keyCompromise);

        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider(new BouncyCastleProvider()).build(caKey);

        X509CRLHolder crlHolder = crlBuilder.build(signer);

        JcaX509CRLConverter converter = new JcaX509CRLConverter().setProvider(new BouncyCastleProvider());
        return converter.getCRL(crlHolder);
    }

    public static Date calculateDate(int hoursInFuture) {
        long secs = System.currentTimeMillis() / 1000;
        return new Date((secs + ((long) hoursInFuture * 60 * 60)) * 1000);
    }
}
