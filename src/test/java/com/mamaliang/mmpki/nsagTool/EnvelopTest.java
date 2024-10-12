package com.mamaliang.mmpki.nsagTool;

import com.mamaliang.mmpki.gmt0016.EnvelopedUtil;
import com.mamaliang.mmpki.gmt0016.SKF_ENVELOPEDKEYBLOB;
import com.mamaliang.mmpki.util.CertUtil;
import com.mamaliang.mmpki.util.PemUtil;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.FileWriter;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @author gaof
 * @date 2024/10/12
 */
@Disabled
public class EnvelopTest {

    private static final String STORE_PATH = "/Users/mamaliang/Workspace/mmlpki/db/";

    /**
     * 已知加密证书私钥、加密证书、签名证书，生成0016信封
     */
    @Test
    public void assembleEnvelop() throws Exception {
        String encPrivateKeyPem = """
                -----BEGIN PRIVATE KEY-----
                MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgnHMsugjNdINpHznj
                6Hmwe1dpZA4ecfKhKgW0dpZVgeGhRANCAATHPM9VI51UWq0WBCGMBa3R63ngP4ts
                6c6jjzN5/WzX/6b5heOeLTAFyIF6ufd0e47F8nT2bPuy61HHHvLtuQX2
                -----END PRIVATE KEY-----""";
        PrivateKey encPrivateKey = PemUtil.pem2privateKey(encPrivateKeyPem);

        String encCertPem = """
                -----BEGIN CERTIFICATE-----
                MIIDczCCAxegAwIBAgIIdMEAQARXlU4wDAYIKoEcz1UBg3UFADBSMQswCQYDVQQG
                EwJDTjEvMC0GA1UECgwmWmhlamlhbmcgRGlnaXRhbCBDZXJ0aWZpY2F0ZSBBdXRo
                b3JpdHkxEjAQBgNVBAMMCVpKQ0EgT0NBMTAeFw0yNDA4MTMxNjAwMDBaFw0yNTA4
                MTQxNTU5NTlaMCQxCzAJBgNVBAYTAkNOMRUwEwYDVQQDDAwxMC41NC4zOC4yMDQw
                WTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATHPM9VI51UWq0WBCGMBa3R63ngP4ts
                6c6jjzN5/WzX/6b5heOeLTAFyIF6ufd0e47F8nT2bPuy61HHHvLtuQX2o4ICATCC
                Af0wDAYDVR0TBAUwAwEBADAOBgNVHQ8BAf8EBAMCADAwFwYDVR0RBBAwDoIMMTAu
                NTQuMzguMjA0MCsGCSsGAQQBgjcUAgQeHhwAUwBtAGEAcgB0AGMAYQByAGQATABv
                AGcAbwBuMB8GA1UdIwQYMBaAFKfTsSSQIB09tFTuSzcoUpGuLGoiMIGxBgNVHR8E
                gakwgaYwgaOggaCggZ2GgZpsZGFwOi8vbGRhcC56amNhLmNvbS5jbi9DTj1aSkNB
                IE9DQTFncm91cDcyODQsQ049WkpDQSBPQ0ExLCBPVT1DUkxEaXN0cmlidXRlUG9p
                bnRzLCBvPXpqY2E/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVj
                dGNsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIGiBggrBgEFBQcBAQSBlTCBkjCB
                jwYIKwYBBQUHMAKGgYJsZGFwOi8vbGRhcC56amNhLmNvbS5jbi9DTj1aSkNBIE9D
                QTEsQ049WkpDQSBPQ0ExLCBPVT1jQUNlcnRpZmljYXRlcywgbz16amNhP2NBQ2Vy
                dGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5
                MB0GA1UdDgQWBBRrAmmtyFNAjIpT7etS7jhxbYVtPzAMBggqgRzPVQGDdQUAA0gA
                MEUCIQDzF4FgeP/59lyxtTY2tEUr/nSzeEXU5PZheDstRRI1KwIgU4XQ+uKJ/KkR
                zhHzFb3YluUUuqnPrZy8oQsR7fNSnzU=
                -----END CERTIFICATE-----""";
        Certificate encCert = PemUtil.pem2Cert(encCertPem);
        PublicKey encPublicKey = CertUtil.extraPublicKey(encCert);

        String sigCertPem = """
                -----BEGIN CERTIFICATE-----
                MIIDbjCCAxKgAwIBAgIIdMEAqwRXlU8wDAYIKoEcz1UBg3UFADBSMQswCQYDVQQG
                EwJDTjEvMC0GA1UECgwmWmhlamlhbmcgRGlnaXRhbCBDZXJ0aWZpY2F0ZSBBdXRo
                b3JpdHkxEjAQBgNVBAMMCVpKQ0EgT0NBMTAeFw0yNDA4MTMxNjAwMDBaFw0yNTA4
                MTQxNTU5NTlaMCQxCzAJBgNVBAYTAkNOMRUwEwYDVQQDDAwxMC41NC4zOC4yMDQw
                WTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAARvdqOfmBh5gomhAB62UIfZNkT8t/G8
                BQSwfIe4dnRb9Sf1J4maRySCkLrvHD808c7bbaSpj10datZX47cdr02no4IB/DCC
                AfgwDAYDVR0TBAUwAwEBADATBgNVHSUEDDAKBggrBgEFBQcDATAOBgNVHQ8BAf8E
                BAMCAMAwEQYJYIZIAYb4QgEBBAQDAgBAMBcGA1UdEQQQMA6CDDEwLjU0LjM4LjIw
                NDAfBgNVHSMEGDAWgBSn07EkkCAdPbRU7ks3KFKRrixqIjCBsQYDVR0fBIGpMIGm
                MIGjoIGgoIGdhoGabGRhcDovL2xkYXAuempjYS5jb20uY24vQ049WkpDQSBPQ0Ex
                Z3JvdXA3Mjg0LENOPVpKQ0EgT0NBMSwgT1U9Q1JMRGlzdHJpYnV0ZVBvaW50cywg
                bz16amNhP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RjbGFz
                cz1jUkxEaXN0cmlidXRpb25Qb2ludDCBogYIKwYBBQUHAQEEgZUwgZIwgY8GCCsG
                AQUFBzAChoGCbGRhcDovL2xkYXAuempjYS5jb20uY24vQ049WkpDQSBPQ0ExLENO
                PVpKQ0EgT0NBMSwgT1U9Y0FDZXJ0aWZpY2F0ZXMsIG89empjYT9jQUNlcnRpZmlj
                YXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTAdBgNV
                HQ4EFgQUTCb4AJgPldn/xx7aDKvYY3la98MwDAYIKoEcz1UBg3UFAANIADBFAiBJ
                hkDhyCA94W1p5AsNLwLA2Yv8LZne6G5CO6YRPkG7AgIhANep2AuNZ9PSEeW5VCOS
                Vx/kaxE2Y8rjeBJaIND+uMRP
                -----END CERTIFICATE-----""";
        Certificate sigCert = PemUtil.pem2Cert(sigCertPem);
        PublicKey sigPublicKey = CertUtil.extraPublicKey(sigCert);

        SKF_ENVELOPEDKEYBLOB envelopedKeyBlob = EnvelopedUtil.assemble((BCECPrivateKey) encPrivateKey, (BCECPublicKey) encPublicKey, (BCECPublicKey) sigPublicKey);
        try (FileWriter assembleEnvelop = new FileWriter(STORE_PATH + "assembleEnvelop.pem")) {
            assembleEnvelop.write(SKF_ENVELOPEDKEYBLOB.toBase64String(envelopedKeyBlob));
        }
    }

    /**
     * 信封内对称算法变更
     * 用于现场没有对接加密机，但ca签发时使用了SM1
     */
    @Test
    public void updateEnvelopFromSM1toSM4() throws Exception {
        String envelop = "AQAAAAEEAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABk9WXsLnNQ+ZTiDYZJC9GeAeizF6FSRKmIHtce+Bdl4gABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMc8z1UjnVRarRYEIYwFrdHreeA/i2zpzqOPM3n9bNf/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACm+YXjni0wBciBern3dHuOxfJ09mz7sutRxx7y7bkF9gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlyj+wkEdkaOvg/fB0/dLN039aHicPiyht215jQvRCE0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI8mxxuOww+5wd40kttqLiyPhrcEIucwnh8u2fOqWIVO+g1dD/2saV3XI46cvlzzrYT70CZ13dsxI4cQzpSEPO4QAAAA6P4BUJHoM7v3BrfpFeihyw==";
        String encCertPem = """
                """;
        String sigCertPem = """
                """;
        String sigPrivateKeyPem = """
                -----BEGIN PRIVATE KEY-----
                MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgnHMsugjNdINpHznj
                6Hmwe1dpZA4ecfKhKgW0dpZVgeGhRANCAATHPM9VI51UWq0WBCGMBa3R63ngP4ts
                6c6jjzN5/WzX/6b5heOeLTAFyIF6ufd0e47F8nT2bPuy61HHHvLtuQX2
                -----END PRIVATE KEY-----""";

        String dynamicLibName = "gm3000.1.0";
        String existEccContainerName = "gaof";

        // 解密出加密证书的私钥
        SKF_ENVELOPEDKEYBLOB eccEnvelopedKeyBlob = SKF_ENVELOPEDKEYBLOB.fromBase64String(envelop);
        PrivateKey sigPrivateKey = PemUtil.pem2privateKey(sigPrivateKeyPem);
        BCECPrivateKey encPrivateKey = EnvelopedUtil.disassemble(eccEnvelopedKeyBlob, (BCECPrivateKey) sigPrivateKey, dynamicLibName, existEccContainerName);

        // 重新组装，重新组装时用的SM4
        Certificate encCert = PemUtil.pem2Cert(encCertPem);
        PublicKey encPublicKey = CertUtil.extraPublicKey(encCert);
        Certificate sigCert = PemUtil.pem2Cert(sigCertPem);
        PublicKey sigPublicKey = CertUtil.extraPublicKey(sigCert);
        SKF_ENVELOPEDKEYBLOB envelopedKeyBlob = EnvelopedUtil.assemble(encPrivateKey, (BCECPublicKey) encPublicKey, (BCECPublicKey) sigPublicKey);
        try (FileWriter assembleEnvelop = new FileWriter(STORE_PATH + "assembleEnvelop.pem")) {
            assembleEnvelop.write(SKF_ENVELOPEDKEYBLOB.toBase64String(envelopedKeyBlob));
        }
    }

}
