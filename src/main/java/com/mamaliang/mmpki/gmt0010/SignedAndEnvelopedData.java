package com.mamaliang.mmpki.gmt0010;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;

import java.util.Enumeration;

/**
 * 对应的oid: 1.2.156.10197.6.1.4.2.4
 * SignedAndEnvelopedData :: = SEQUENCE {
 * version                 Version,
 * recipientInfos          RecipientInfos,
 * digestAlgorithms        DigestAlgorithmIdentifiers,
 * encryptedContentInfo    EncryptedContentInfo,
 * certificates[0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL,
 * erls[1] IMPLICIT CertificateRevocationLists OPTIONAL,
 * signerInfos SignerInfos
 * }
 *
 * @author gaof
 * @date 2023/12/25
 */
public class SignedAndEnvelopedData extends ASN1Object {

    public static final ASN1ObjectIdentifier OBJECT_IDENTIFIER = new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.4");

    private final ASN1Integer version;
    private final ASN1Set recipientInfos;
    private final ASN1Set digestAlgorithms;
    private final EncryptedContentInfo encryptedContentInfo;
    private ASN1Set certificates;
    private ASN1Set crls;
    private final ASN1Set signerInfos;

    public SignedAndEnvelopedData(ASN1Sequence seq) {
        Enumeration<?> e = seq.getObjects();
        version = ASN1Integer.getInstance(e.nextElement());
        recipientInfos = ASN1Set.getInstance(e.nextElement());
        digestAlgorithms = ASN1Set.getInstance(e.nextElement());
        encryptedContentInfo = EncryptedContentInfo.getInstance(e.nextElement());
        ASN1Set sigInfs = null;
        while (e.hasMoreElements()) {
            ASN1Primitive o = (ASN1Primitive) e.nextElement();
            if (o instanceof ASN1TaggedObject) {
                ASN1TaggedObject tagged = (ASN1TaggedObject) o;
                switch (tagged.getTagNo()) {
                    case 0:
                        certificates = ASN1Set.getInstance(tagged, false);
                        break;
                    case 1:
                        crls = ASN1Set.getInstance(tagged, false);
                        break;
                    default:
                        throw new IllegalArgumentException("unknown tag value " + tagged.getTagNo());
                }
            } else {
                if (!(o instanceof ASN1Set)) {
                    throw new IllegalArgumentException("SET expected, not encountered");
                }
                sigInfs = ASN1Set.getInstance(o);
            }
        }
        if (sigInfs == null) {
            throw new IllegalArgumentException("signerInfos not set");
        }
        signerInfos = sigInfs;
    }

    public ASN1Integer getVersion() {
        return version;
    }

    public ASN1Set getRecipientInfos() {
        return recipientInfos;
    }

    public ASN1Set getDigestAlgorithms() {
        return digestAlgorithms;
    }

    public EncryptedContentInfo getEncryptedContentInfo() {
        return encryptedContentInfo;
    }

    public ASN1Set getCertificates() {
        return certificates;
    }

    public ASN1Set getCrls() {
        return crls;
    }

    public ASN1Set getSignerInfos() {
        return signerInfos;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return null;
    }

}
