package com.mamaliang.mmpki.nsagTool;

import com.mamaliang.mmpki.util.PemUtil;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.Disabled;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.Hashtable;

/**
 * @author gaof
 * @date 2025/5/16
 */
@Disabled
public class SvsTest {

    /**
     * 生成attach模式并携带认证属性的P7签名
     * 简单实现，默认采用SHA256withRSA
     *
     * @param certificate 证书
     * @param privateKey  私钥
     * @param plainText   签名原文
     * @return P7格式签名字节数组
     */
    public static byte[] generateP7Signature(Certificate certificate, PrivateKey privateKey, byte[] plainText) throws CertificateEncodingException, OperatorCreationException, CMSException, NoSuchAlgorithmException, IOException {

        // 1. 计算原文的摘要
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] messageDigest = digest.digest(plainText);

        // 2. 创建认证属性(包含计算出的messageDigest)，这个才是真正的原文
        AttributeTable signedAttributes = createSignedAttributes(messageDigest);

        // 3. 创建摘要计算器提供者
        DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder()
                .setProvider(new BouncyCastleProvider())
                .build();

        // 4. 创建签名信息生成器并设置认证属性
        JcaSignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider)
                .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(signedAttributes));

        // 5. 创建CMS签名数据生成器
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        // 6. 创建内容签名者
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(new BouncyCastleProvider())
                .build(privateKey);

        // 7. 构建签名信息生成器并添加到CMS生成器
        gen.addSignerInfoGenerator(signerInfoGeneratorBuilder.build(signer, new X509CertificateHolder(certificate)));

        // 8. 添加证书
        gen.addCertificates(new JcaCertStore(Collections.singleton(new X509CertificateHolder(certificate))));

        // 9. 生成Attach模式的签名数据
        CMSSignedData signedData = gen.generate(new CMSProcessableByteArray(plainText), true);

        System.out.println(Base64.getEncoder().encodeToString(signedData.getEncoded()));

        return signedData.getEncoded();
    }

    /**
     * 创建认证属性
     */
    private static AttributeTable createSignedAttributes(byte[] messageDigest) {
        Hashtable<ASN1ObjectIdentifier, Attribute> attributes = new Hashtable<>();

        // 1. 添加内容类型属性 1.2.840.113549.1.9.3 -> 1.2.840.113549.1.7.1
        attributes.put(PKCSObjectIdentifiers.pkcs_9_at_contentType, new Attribute(PKCSObjectIdentifiers.pkcs_9_at_contentType, new DERSet(PKCSObjectIdentifiers.data)));

        // 2. 添加消息摘要属性 (1.2.840.113549.1.9.4)
        attributes.put(PKCSObjectIdentifiers.pkcs_9_at_messageDigest, new Attribute(PKCSObjectIdentifiers.pkcs_9_at_messageDigest, new DERSet(new DEROctetString(messageDigest))));

        // 3. 添加签名时间属性 1.2.840.113549.1.9.5
        ASN1UTCTime signingTime = new ASN1UTCTime(new Date());
        attributes.put(PKCSObjectIdentifiers.pkcs_9_at_signingTime, new Attribute(PKCSObjectIdentifiers.pkcs_9_at_signingTime, new DERSet(signingTime)));

        return new AttributeTable(attributes);
    }

    public static void main(String[] args) {
        try {
            String certificateString = """
                    -----BEGIN CERTIFICATE-----
                    MIIEEDCCAvigAwIBAgIMSeoAAAAAC+vjc6prMA0GCSqGSIb3DQEBCwUAMIGJMQsw
                    CQYDVQQGEwJDTjEPMA0GA1UECAwG5LiK5rW3MRIwEAYDVQQHDAnkuIrmtbfluIIx
                    LTArBgNVBAoMJOS4iua1t+agvOWwlOi9r+S7tuiCoeS7veaciemZkOWFrOWPuDEV
                    MBMGA1UECwwM5qC85bCU6L2v5Lu2MQ8wDQYDVQQDDAZLb2FsQ2EwHhcNMjEwMzMx
                    MTYwMDAwWhcNMjYwNDAxMTU1OTU5WjBTMQswCQYDVQQGEwJDTjEVMBMGA1UECgwM
                    5qC85bCU6L2v5Lu2MRwwGgYJKoZIhvcNAQkBFg1nYW9mQGtvYWwuY29tMQ8wDQYD
                    VQQDDAbpq5jls7AwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9ewti
                    6+vy+o44kgv3w4U51/ee1IEFDJwQaVg5sJC0dTFR8MeptKJYZ2pcogEzvkYuXBuH
                    fK93DCRNxBoZBdbOn9FZtw4j56u+pohrElR2NNl9HZ/HS+8jFeWzBlPvd/SCD9Ef
                    WjNr1gxkLmDZBaly+Z2IhLgMDPpFEqbzK9mOZmzOnKqJAAYfG87L2C+p/fZVFEHI
                    8/0pwBVL+9uywpj8wCqhCpXg4gSlHBERhdVBvP9+X4i3mnPVocwzZi78/8NgwzJE
                    gG/0tET3q22wu9ub8slyMkHUn3okRBASH5owaD4L42FizmxPUhOGrJLK5MmFKaES
                    c3fpdTWQUux9pSJ3AgMBAAGjgawwgakwDAYDVR0TBAUwAwEBADAfBgNVHSUEGDAW
                    BggrBgEFBQcDBAYKKwYBBAGCNxQCAjALBgNVHQ8EBAMCADAwKwYJKwYBBAGCNxQC
                    BB4eHABTAG0AYQByAHQAYwBhAHIAZABMAG8AZwBvAG4wHwYDVR0jBBgwFoAU19j8
                    SB4iZlPUQdMnWtwMvzt0aaMwHQYDVR0OBBYEFK59Krv4saJYzatwdxgbUq3NUOZJ
                    MA0GCSqGSIb3DQEBCwUAA4IBAQAA8bSX1h+VRohvByjULbULA9xiAJRVGQunEpGM
                    cqORng+u+3r1qqkIt6BhjMi8AxD0qYyDqXtZQBAbfjaHExGpVkUSs10aA+krKSCU
                    BUsvx/3jEbS0tRPEzSFW4lmt7FZCzpI+FYFNC+vNf5cJKATTYjtIREShI3ZGglwX
                    M6aa3y6hE3gI31St6386BXWECsX7CFJBc7XGvUl7W8/AgBjL/UEjkZO2pbOzX86W
                    PpyVRnez1GPWl5UZIbv2cxay4TAipv8ZJI5J1M4aqfbBV3bt7fz5f2PudHj5zM8O
                    sUjgaXNz2xwdlC9Vi89TRKV8dJiYSHPlwhN29l3lOo3eC2Cb
                    -----END CERTIFICATE-----""";
            Certificate certificate = PemUtil.pem2Cert(certificateString);

            String privateKeyString = """
                    -----BEGIN PRIVATE KEY-----
                    MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC9ewti6+vy+o44
                    kgv3w4U51/ee1IEFDJwQaVg5sJC0dTFR8MeptKJYZ2pcogEzvkYuXBuHfK93DCRN
                    xBoZBdbOn9FZtw4j56u+pohrElR2NNl9HZ/HS+8jFeWzBlPvd/SCD9EfWjNr1gxk
                    LmDZBaly+Z2IhLgMDPpFEqbzK9mOZmzOnKqJAAYfG87L2C+p/fZVFEHI8/0pwBVL
                    +9uywpj8wCqhCpXg4gSlHBERhdVBvP9+X4i3mnPVocwzZi78/8NgwzJEgG/0tET3
                    q22wu9ub8slyMkHUn3okRBASH5owaD4L42FizmxPUhOGrJLK5MmFKaESc3fpdTWQ
                    Uux9pSJ3AgMBAAECggEAbytpA9HtbnLIzLILaYOCf+yRMNP3GrJKQmq8Q6SvUeFM
                    XYoKayw67+lFAzJdyDED1iFeWYCzJgKurh23PiUp4bLszllTZ4d+QW5NrZxkh7H8
                    RKcD3pdTp98qFH5K8r4La9/Bz0ZJ0yQTwxde5RWoVHfVkIplvVRD5hDKePOqQhwb
                    mB8QNwrw2iDjpplsbDKJzw9vt2U9OyRWB5hgfE7iy/GhV/lKsAo9pBKLgmFAILTz
                    VDVW1t06m1TeP+vEU8VJNQV5YcHbNQVVuHbik9izum8KIgeJt5FAoN+AXwTPdOB3
                    4XGD7lI3bPEjON7KQQENympbJRZGXi/2t73hu0bw6QKBgQD5hASqhK3Sh6K3I4yN
                    9fm87oH3NUDnnqWGBcY5OfLiHGNMtNwt3+V69rFY5xdAvR++xdDWgon3rwQk0t/t
                    p0VAmlAS7893aMMYxZHz5RATBoZD5YhAmlpdnnAhTl1Rr17xgjsuAr7+0pmYW0d4
                    JkvDrg8Y5+t7QmuRU/vgB7jpwwKBgQDCZ5/H5AXgfrNzIEFwOYoX0j8u5RQT7EjD
                    iePnFTie+diYDtnaqaZNF9DOfWxfftJJ7y4vGZ0dc+/H5uR9CDGxVNDqRejKUntA
                    QBqB6BdnR1etzV30Q54lK6Ip75ssB9Z5id4RD9iHaWVYAm3kPkWHRZpCLsvLOMMM
                    nMSZmv7lPQKBgQDQoioApuZtRkqxVcE+JrIG32u+2EGIKqh/Ey73RNQpatFBH22H
                    0lIg6kvKaZiQ4lK8As4nv4k7mJUfcVAaeKY4aY+Q9gKE9w1DFlh/FkbFkcwM082F
                    L0tmQofB4bO4DKqXyGxRgaxQiKozsgdlmKf7W/x1t9639wbYwt+2KN7eXwKBgQCg
                    1PAIhGokR04Y4cehm8jWWldxaY3JycKNGygUBqd4RoVdj3PGhnIR97EFFBizjI1X
                    I2yXBN7J/h+Sxz+i/UN3TQ8lsj6cG87h4ebMMIIkLI6qOGwRaFuOruGTRiqfK8DR
                    fjDc9roRlS2FuUTG/omxFvE+7c4mS8h6R7wSxHs6lQKBgFvx218uhxb1JSvwvDT8
                    CWzO46ZqzeMIBI5f3iqG1Gp8wOGsUvzcYYTJjwCO2dPrmBDkwyohbD7Qezv9mujm
                    bryzqXll77boHzENUrLULMlV1duiBHlY11QiJxPTOFn9PKRS5H9qt1oksG1Gb2kO
                    hVQUO8CPkpNYbGerx/1t5gMU
                    -----END PRIVATE KEY-----""";
            PrivateKey privateKey = PemUtil.pem2privateKey(privateKeyString);

            byte[] randomData = "zheshiyigecheshishuijishu".getBytes(); // 替换为你的随机数

            // 生成P7签名
            byte[] p7Signature = generateP7Signature(certificate, privateKey, randomData);

            System.out.println("Attach模式的P7签名生成成功，长度: " + p7Signature.length + "字节");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
