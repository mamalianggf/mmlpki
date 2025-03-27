package com.mamaliang.mmpki.nsagTool;

import com.mamaliang.mmpki.algorithm.SM2;
import com.mamaliang.mmpki.gmt0016.EnvelopedUtil;
import com.mamaliang.mmpki.gmt0016.SKFUtil;
import com.mamaliang.mmpki.gmt0016.SKF_ENVELOPEDKEYBLOB;
import com.mamaliang.mmpki.gmt0016.Struct_ECCPUBLICKEYBLOB;
import com.mamaliang.mmpki.util.CertUtil;
import com.mamaliang.mmpki.util.PemUtil;
import com.mamaliang.mmpki.util.PropertiesUtil;
import com.mamaliang.mmpki.util.X500NameUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.FileWriter;
import java.security.KeyPair;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * 需连接usbkey
 *
 * @author gaof
 * @date 2024/1/5
 */
@Disabled
public class GM3000Test {

    private static final String STORE_PATH = PropertiesUtil.getString("cert.store.path");
    private static final String DYNAMIC_LIB_NAME = PropertiesUtil.getString("usbKey.dynamicLib.name");
    private static final String USER_PIN = PropertiesUtil.getString("usbKey.user.pin");

    @Test
    void list() {
        // 展示
        List<List<String>> containersPath = SKFUtil.listContainer();
        containersPath.forEach(System.out::println);
    }

    @Test
    void delete() {
        // 删除
        SKFUtil.deleteContainer("CEC45107E789B945960BFF6BB31BCB7", "GM3000RSA", "test");
    }

    @Test
    void createAndGenerateAndImport() {
        // 1.创建容器 2.生成签名密钥对 3.密钥不落地形式导入
        SKFUtil.createContainer("CEC45107E789B945960BFF6BB31BCB7", "GM3000RSA", "test");
        generateAndImportCertsWithEnvelop("CEC45107E789B945960BFF6BB31BCB7", "GM3000RSA", "test");
    }

    @Test
    void sm1() {

    }


    void generateAndImportCertsWithEnvelop(String devName, String applicationName, String containerName) {
        try {
            // 生成签名密钥对
            Struct_ECCPUBLICKEYBLOB eccPublicKeyBlob = SKFUtil.genECCKeyPair(devName, applicationName, containerName);
            // 签名公钥
            BCECPublicKey bcecPublicKey = SM2.convert2PublicKey(eccPublicKeyBlob.XCoordinate, eccPublicKeyBlob.YCoordinate);

            // 临时ca，用于签发签名证书和加密证书
            X500Name caName = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "SM2ROOT");
            Date notBefore = new Date();
            Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年
            KeyPair caKeyPair = SM2.generateKeyPair();
            Certificate sm2ROOT = CertUtil.selfIssueCert(true, false, false, caName, notBefore, notAfter, Collections.singletonList("SM2ROOT"), caKeyPair, SM2.SIGNATURE_SM3_WITH_SM2);
            try (FileWriter caCertFile = new FileWriter(STORE_PATH + "ca.pem");
                 FileWriter caKeyFile = new FileWriter(STORE_PATH + "ca.key")) {
                caCertFile.write(PemUtil.cert2pem(sm2ROOT));
                caKeyFile.write(PemUtil.privateKey2pem(caKeyPair.getPrivate()));
            }

            String commonName = "gaof";
            // 临时ca签发签名证书
            X500Name siteName = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", commonName);
            Certificate sm2SIG = CertUtil.caIssueCert(false, true, false, siteName, bcecPublicKey, notBefore, notAfter, caName, CertUtil.generateSANExt(Collections.singletonList(commonName)), caKeyPair.getPublic(), caKeyPair.getPrivate(), SM2.SIGNATURE_SM3_WITH_SM2);
            // 生成加密密钥对
            KeyPair encKeyPair = SM2.generateKeyPair();
            // 将加密私钥封装成信封
            SKF_ENVELOPEDKEYBLOB envelop = EnvelopedUtil.assemble((BCECPrivateKey) encKeyPair.getPrivate(), (BCECPublicKey) encKeyPair.getPublic(), bcecPublicKey);
            // 临时ca签发签名证书
            Certificate sm2ENC = CertUtil.caIssueCert(false, false, true, siteName, encKeyPair.getPublic(), notBefore, notAfter, caName, CertUtil.generateSANExt(Collections.singletonList(commonName)), caKeyPair.getPublic(), caKeyPair.getPrivate(), SM2.SIGNATURE_SM3_WITH_SM2);

            // 导入签名证书、信封、加密证书
            SKFUtil.importCertsWithEnvelop(devName, applicationName, containerName, sm2SIG, envelop, sm2ENC);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
