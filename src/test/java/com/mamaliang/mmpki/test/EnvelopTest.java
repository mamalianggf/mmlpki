package com.mamaliang.mmpki.test;

import com.mamaliang.mmpki.algorithm.SM2;
import com.mamaliang.mmpki.cert.model.*;
import com.mamaliang.mmpki.cert.service.impl.SM2CertServiceImpl;
import com.mamaliang.mmpki.gmt0009.SM2EnvelopedKey;
import com.mamaliang.mmpki.gmt0010.SignedAndEnvelopedData;
import com.mamaliang.mmpki.gmt0016.EnvelopedUtil;
import com.mamaliang.mmpki.gmt0016.SKF_ENVELOPEDKEYBLOB;
import com.mamaliang.mmpki.util.CertUtil;
import com.mamaliang.mmpki.util.PemUtil;
import com.mamaliang.mmpki.util.X500NameUtil;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * @author gaof
 * @date 2023/11/21
 */
public class EnvelopTest {

    @Test
    void testConvertAnXinCa0010() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        String b64EncCert = """
                -----BEGIN CERTIFICATE-----
                MIIDVzCCAvugAwIBAgIQRhJy7al+XUcIWbQcfGPhVzAMBggqgRzPVQGDdQUAMDcx
                CzAJBgNVBAYTAkNOMREwDwYDVQQKDAhBblhpbiBDQTEVMBMGA1UEAwwMQW5YaW4g
                U00yIENBMB4XDTIzMTIyODAxMzYzMFoXDTI0MDEyNzAxMzYzMFowHTELMAkGA1UE
                BhMCQ04xDjAMBgNVBAMMBXN6d2R0MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE
                fNYG49HbeFc/JHnb7ucfywO2dhTq9nSEOdXI2Ak53/oZSk/XHFMJusbgfjDT71EB
                85kosupdvFeoYrIsY4/6XqOCAf8wggH7MA4GA1UdDwEB/wQEAwIEMDAdBgNVHSUE
                FjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFGYlR0K9C+0OXT7NR8Ph
                1BWggTQzMIHwBgNVHR8EgegwgeUwM6AxoC+kLTArMQswCQYDVQQGEwJDTjEMMAoG
                A1UECwwDQ1JMMQ4wDAYDVQQDDAVjcmw3MDAzoDGgL4YtaHR0cDovL2Nvbm5lY3Rv
                ci5hbnhpbmNhLmNvbS9zbTJjcmwvY3JsNzAuY3JsMHmgd6B1hnNsZGFwOi8vc20y
                bGRhcC5hbnhpbmNhLmNvbTozOTAvQ049Y3JsNzAsT1U9Q1JMLEM9Q04/Y2VydGlm
                aWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdGNsYXNzPWNSTERpc3RyaWJ1
                dGlvblBvaW50MHcGCCsGAQUFBwEBBGswaTAmBggrBgEFBQcwAYYaaHR0cDovLzIy
                MS44LjE2LjEwNzoyMDQ0NC8wPwYIKwYBBQUHMAKGM2h0dHA6Ly93d3cuYW54aW5j
                YS5jb20vZG93bmxvYWQtZmlsZS9BblhpblNNMkNBLmNlcjAQBgNVHREECTAHggVz
                endkdDAfBgNVHSMEGDAWgBS7f/leOGn4WWcJqnfhxoMEGOkBFTAMBgNVHRMEBTAD
                AQEAMAwGCCqBHM9VAYN1BQADSAAwRQIhANa19GRBWIBdNNzh1VK24cYb/P71pg2X
                keBxldquqVW5AiB+vsZFIwtekh0gw4dkVQ55ykNrZkJsSubTL84yIr5mxA==
                -----END CERTIFICATE-----""";
        Certificate encCert = PemUtil.pem2Cert(b64EncCert);
        SubjectPublicKeyInfo subjectPublicKeyInfo = encCert.getSubjectPublicKeyInfo();
        String algo = subjectPublicKeyInfo.getAlgorithm().getAlgorithm().getId();
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance(algo, new BouncyCastleProvider());
        BCECPublicKey publicKey = (BCECPublicKey) keyFactory.generatePublic(x509EncodedKeySpec);

        String b640010 = "MIIEoQIBATGB3jCB2wIBADBLMDcxCzAJBgNVBAYTAkNOMREwDwYDVQQKDAhBblhpbiBDQTEVMBMGA1UEAwwMQW5YaW4gU00yIENBAhAru/ZEdRMlOxW5Z+SnDngSMAsGCSqBHM9VAYItAwR8MIF5AiEA182oc9losF0H7a8UrCjGLYwI1s2SbCCly5cnSk6wxJQCIDKPfkcoVR0WofHNvVtSGrc68E9Ry+rQxLy4YwSFqz6QBCCJ3spajMQkPqbq11Rh2Qy10UsrmiUdjezBGVVdnXnfBwQQl4Z9jnuCcuTYKqRYrDuXLDEMMAoGCCqBHM9VAYMRMFkGCiqBHM9VBgEEAgEwCQYHKoEcz1UBaIBAjjy5TrZFer36oqoaBMn+l448uU62RXq9+qKqGgTJ/pfSGhUdjrYlHMwW1pl+2FX7tHJGgzZ1I63Gag2jF2LdE6CCApgwggKUMIICN6ADAgECAhAeabAJXKnslWV/wZCSf0ejMAwGCCqBHM9VAYN1BQAwNzELMAkGA1UEBhMCQ04xETAPBgNVBAoMCEFuWGluIENBMRUwEwYDVQQDDAxBblhpbiBTTTIgQ0EwHhcNMTYwMzEzMDcyNTMwWhcNMjYwMzExMDcyNTMwWjAkMQswCQYDVQQGEwJDTjEVMBMGA1UEAxMMS01TaWduZWREYXRhMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEQNxLiH/zJj7XJ2zZsoCOHaGX+zH0Wcsv0NIrUrYOn3hBow35Bc/pLkveM8aBOjnY3XF5gu+YM5evqNoZ3HPbI6OCATQwggEwMB8GA1UdIwQYMBaAFLt/+V44afhZZwmqd+HGgwQY6QEVMB0GA1UdDgQWBBQU48RxBnuAWRCnDV34f1UlM5+LyDCB7QYDVR0fBIHlMIHiMDKgMKAupCwwKjELMAkGA1UEBhMCQ04xDDAKBgNVBAsTA0NSTDENMAsGA1UEAxMEY3JsMTAyoDCgLoYsaHR0cDovL2Nvbm5lY3Rvci5hbnhpbmNhLmNvbS9zbTJjcmwvY3JsMS5jcmwweKB2oHSGcmxkYXA6Ly9zbTJsZGFwLmFueGluY2EuY29tOjM5MC9DTj1jcmwxLE9VPUNSTCxDPUNOP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RjbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDAMBggqgRzPVQGDdQUAA0kAMEYCIQC5E/LBMrhmb1ZAl57IZJgSGMhMZ4ErElCPlJRt2h6CUQIhAIH4xqB8h3HM/8BbQkJKRcEct71eAJHbo77L/FtoNAgPMYG1MIGyAgEBMEswNzELMAkGA1UEBhMCQ04xETAPBgNVBAoMCEFuWGluIENBMRUwEwYDVQQDDAxBblhpbiBTTTIgQ0ECEB5psAlcqeyVZX/BkJJ/R6MwCgYIKoEcz1UBgxEwCwYJKoEcz1UBgi0BBEcwRQIhAPfeIFjSEER6+A0yQUVuw6CYKdCaZKkZip/LJH97eapJAiBJA4U6C+pr/Ez3nZigpXnm5frQImzJuOHTcvqkMGiYIA==";
        byte[] b0010 = Base64.getDecoder().decode(b640010.getBytes(StandardCharsets.UTF_8));
        ASN1Sequence allSeq = ASN1Sequence.getInstance(b0010);

        SignedAndEnvelopedData signedAndEnvelopedData = new SignedAndEnvelopedData(allSeq);
        // 加密证书或者加密公钥貌似在signedAndEnvelopedData中找不到
        String b640016 = EnvelopedUtil.convertAnXinCa0010(signedAndEnvelopedData, publicKey);

        String exceptB640016 = "AQAAAAEEAAAAAQAAjjy5TrZFer36oqoaBMn+l448uU62RXq9+qKqGgTJ/pfSGhUdjrYlHMwW1pl+2FX7tHJGgzZ1I63Gag2jF2LdEwABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHzWBuPR23hXPyR52+7nH8sDtnYU6vZ0hDnVyNgJOd/6AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZSk/XHFMJusbgfjDT71EB85kosupdvFeoYrIsY4/6XgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA182oc9losF0H7a8UrCjGLYwI1s2SbCCly5cnSk6wxJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADKPfkcoVR0WofHNvVtSGrc68E9Ry+rQxLy4YwSFqz6Qid7KWozEJD6m6tdUYdkMtdFLK5olHY3swRlVXZ153wcQAAAAl4Z9jnuCcuTYKqRYrDuXLA==";
        Assertions.assertEquals(exceptB640016, b640016);
    }

    @Test
    void testConvert0009() {
        String b640009 = "MIHtMAoGCCqBHM9VAWgBMHgCIKkJ2Foch3yAJwePgEfyiTp89gXbQBuiP+E/cfNfyKc2AiDGumD7Z/+BrXxyWwd+RX4RpJReqvLsMovdvYKpTOK6FwQg/z2rwBNakQyXaxZVWhmA+wouSa+UC1W81JDcgyrL4mAEEHMbi2iFnaz/9YCBIMMKnD0DQgAEFR0+cdVs1/Zs/b4Ss7egN+R0TVS7UBIGc1ZK82xbB8E3wG5pMPczhtN5rdf27BVxZ8xglVZ0b7zwYm+5+H2lfQMhAFJrQ0LmgUxxsa+k9pWmfZ69nGu7Tar5lGNqn5m1GuSe";
        byte[] b0009 = Base64.getDecoder().decode(b640009.getBytes(StandardCharsets.UTF_8));
        ASN1Sequence allSeq = ASN1Sequence.getInstance(b0009);
        SM2EnvelopedKey sm2EnvelopedKey = new SM2EnvelopedKey(allSeq);
        String b640016 = EnvelopedUtil.convert0009(sm2EnvelopedKey);
        String exceptB640016 = "AQAAAAEEAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSa0NC5oFMcbGvpPaVpn2evZxru02q+ZRjap+ZtRrkngABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABUdPnHVbNf2bP2+ErO3oDfkdE1Uu1ASBnNWSvNsWwfBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA3wG5pMPczhtN5rdf27BVxZ8xglVZ0b7zwYm+5+H2lfQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqQnYWhyHfIAnB4+AR/KJOnz2BdtAG6I/4T9x81/IpzYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMa6YPtn/4GtfHJbB35FfhGklF6q8uwyi929gqlM4roX/z2rwBNakQyXaxZVWhmA+wouSa+UC1W81JDcgyrL4mAQAAAAcxuLaIWdrP/1gIEgwwqcPQ==";
        Assertions.assertEquals(exceptB640016, b640016);
    }

    @Test
    void testEnvelop() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidCipherTextException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        String caCommonName = "SM2ROOTCA";
        String commonName = "www.test.com";

        // 签发证书请求
        CsrVO csrvo = new CsrVO();
        X500Name siteDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", commonName);
        csrvo.setSubjectDn(siteDn);
        List<String> sans = Collections.singletonList(commonName);
        csrvo.setSubjectAltNames(sans);
        CsrWithPrivateKey csrWithPrivateKey = new SM2CertServiceImpl().generateCsr(csrvo);
        // 自签发ca证书
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年
        SelfIssueCertVO svo = new SelfIssueCertVO();
        X500Name caDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", caCommonName);
        svo.setSubjectDn(caDn);
        svo.setCa(false);
        svo.setNotBefore(notBefore);
        svo.setNotAfter(notAfter);
        svo.setSubjectAltNames(Collections.singletonList(caCommonName));
        CertWithPrivateKey caCertWithPrivateKey = new SM2CertServiceImpl().selfIssueSingleCert(svo);
        // ca签发双证书(信封)
        CaIssueCertVO cvo = new CaIssueCertVO();
        cvo.setCa(false);
        cvo.setNotBefore(notBefore);
        cvo.setNotAfter(notAfter);
        cvo.setCsr(csrWithPrivateKey.csr());
        cvo.setCaCert(caCertWithPrivateKey.cert());
        cvo.setCaPrivateKey(caCertWithPrivateKey.privateKey());
        DoubleCertWithEnvelop doubleCertWithEnvelop = new SM2CertServiceImpl().caIssueDoubleCertWithEnvelop(cvo);
        // 从信封解出来的私钥和证书中的公钥的是否为一对
        BCECPublicKey encPublic = (BCECPublicKey) CertUtil.extraPublicKey(PemUtil.pem2Cert(doubleCertWithEnvelop.encCert()));
        BCECPrivateKey encPrivate = EnvelopedUtil.disassemble(SKF_ENVELOPEDKEYBLOB.fromBase64String(doubleCertWithEnvelop.envelop()), (BCECPrivateKey) PemUtil.pem2privateKey(csrWithPrivateKey.privateKey()));
        String plainText = "hello world";
        byte[] encrypt = SM2.encrypt(encPublic, plainText.getBytes(StandardCharsets.UTF_8));
        byte[] decrypt = SM2.decrypt(encPrivate, encrypt);
        String text = new String(decrypt, StandardCharsets.UTF_8);
        Assertions.assertEquals(plainText, text);
    }

    @Test
    void test() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidCipherTextException {
        KeyPair keyPair = SM2.generateKeyPair();
        String plainText = "hello world";
        byte[] encrypt = SM2.encrypt((BCECPublicKey) keyPair.getPublic(), plainText.getBytes(StandardCharsets.UTF_8));
        byte[] decrypt = SM2.decrypt((BCECPrivateKey) keyPair.getPrivate(), encrypt);
        String text = new String(decrypt, StandardCharsets.UTF_8);
        Assertions.assertEquals(plainText, text);
    }

}
