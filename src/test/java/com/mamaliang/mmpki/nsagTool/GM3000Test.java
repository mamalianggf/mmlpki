package com.mamaliang.mmpki.nsagTool;

import com.mamaliang.mmpki.algorithm.SM2;
import com.mamaliang.mmpki.gmt0016.EnvelopedUtil;
import com.mamaliang.mmpki.gmt0016.SKFLibraryWrapper;
import com.mamaliang.mmpki.gmt0016.SKF_ENVELOPEDKEYBLOB;
import com.mamaliang.mmpki.gmt0016.Struct_ECCPUBLICKEYBLOB;
import com.mamaliang.mmpki.util.CertUtil;
import com.mamaliang.mmpki.util.PemUtil;
import com.mamaliang.mmpki.util.X500NameUtil;
import com.sun.jna.Pointer;
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
import java.util.Objects;

/**
 * 需连接usbkey
 *
 * @author gaof
 * @date 2024/1/5
 */
@Disabled
public class GM3000Test {

    private static final String STORE_PATH = "/Users/mamaliang/Workspace/mmlpki/db/";
    private static final String DYNAMIC_LIB_NAME = "gm3000.1.0";
    private static final String USER_PIN = "12345678";

    @Test
    void operate() {
        String containerName = "gaof";
        String cn = "gaof";
        // 展示
        listContainer();
        // 删除
//        deleteContainer(containerName);
        // 1.创建容器 2.生成签名密钥对 3.密钥不落地形式导入
//        createContainer(containerName);
//        makeContainer(containerName, cn);
    }

    void listContainer() {
        SKFLibraryWrapper skf = null;
        Pointer hDev = null;
        Pointer hApplication = null;
        try {
            skf = new SKFLibraryWrapper(DYNAMIC_LIB_NAME);
            List<String> devNames = skf.enumDev();
            hDev = skf.connectDev(devNames.get(0));
            List<String> applicationNames = skf.enumApplication(hDev);
            hApplication = skf.openApplication(hDev, applicationNames.get(0));
            skf.enumContainer(hApplication);
        } finally {
            if (Objects.nonNull(skf)) {
                if (Objects.nonNull(hApplication)) {
                    skf.closeApplication(hApplication);
                }
                if (Objects.nonNull(hDev)) {
                    skf.disConnectDev(hDev);
                }
            }
        }
    }

    void deleteContainer(String containerName) {
        SKFLibraryWrapper skf = null;
        Pointer hDev = null;
        Pointer hApplication = null;
        try {
            skf = new SKFLibraryWrapper(DYNAMIC_LIB_NAME);
            List<String> devNames = skf.enumDev();
            hDev = skf.connectDev(devNames.get(0));
            List<String> applicationNames = skf.enumApplication(hDev);
            hApplication = skf.openApplication(hDev, applicationNames.get(0));
            skf.enumContainer(hApplication);
            // 辉哥的key,目前只知道用户pin码是12345678,管理员pin码和设备认证码都不知道
            skf.verifyPIN(hApplication, 1, USER_PIN);
            skf.deleteContainer(hApplication, containerName);
            skf.enumContainer(hApplication);
        } finally {
            if (Objects.nonNull(skf)) {
                if (Objects.nonNull(hApplication)) {
                    skf.closeApplication(hApplication);
                }
                if (Objects.nonNull(hDev)) {
                    skf.disConnectDev(hDev);
                }
            }
        }
    }

    void createContainer(String containerName) {
        SKFLibraryWrapper skf = null;
        Pointer hDev = null;
        Pointer hApplication = null;
        try {
            skf = new SKFLibraryWrapper(DYNAMIC_LIB_NAME);
            List<String> devNames = skf.enumDev();
            hDev = skf.connectDev(devNames.get(0));
            List<String> applicationNames = skf.enumApplication(hDev);
            hApplication = skf.openApplication(hDev, applicationNames.get(0));
            skf.enumContainer(hApplication);
            // 辉哥的key,目前只知道用户pin码是12345678,管理员pin码和设备认证码都不知道
            skf.verifyPIN(hApplication, 1, USER_PIN);
            skf.createContainer(hApplication, containerName);
            skf.enumContainer(hApplication);
        } finally {
            if (Objects.nonNull(skf)) {
                if (Objects.nonNull(hApplication)) {
                    skf.closeApplication(hApplication);
                }
                if (Objects.nonNull(hDev)) {
                    skf.disConnectDev(hDev);
                }
            }
        }
    }

    void makeContainer(String containerName, String cn) {
        SKFLibraryWrapper skf = null;
        Pointer hDev = null;
        Pointer hApplication = null;
        Pointer hContainer = null;
        try {
            skf = new SKFLibraryWrapper(DYNAMIC_LIB_NAME);
            List<String> devNames = skf.enumDev();
            hDev = skf.connectDev(devNames.get(0));
            List<String> applicationNames = skf.enumApplication(hDev);
            hApplication = skf.openApplication(hDev, applicationNames.get(0));
            hContainer = skf.openContainer(hApplication, containerName);
            skf.verifyPIN(hApplication, 1, USER_PIN);
            Struct_ECCPUBLICKEYBLOB eccPublicKeyBlob = skf.genECCKeyPair(hContainer);
            BCECPublicKey bcecPublicKey = SM2.convert2PublicKey(eccPublicKeyBlob.XCoordinate, eccPublicKeyBlob.YCoordinate);
            // ca cert
            X500Name caName = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "SM2ROOT");
            Date notBefore = new Date();
            Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年
            KeyPair caKeyPair = SM2.generateKeyPair();
            Certificate sm2ROOT = CertUtil.selfIssueCert(true, false, false, caName, notBefore, notAfter, Collections.singletonList("SM2ROOT"), caKeyPair, SM2.SIGNATURE_SM3_WITH_SM2);
            // sig cert and enc key pair and enc cert
            X500Name siteName = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", cn);
            Certificate sm2SIG = CertUtil.caIssueCert(false, true, false, siteName, bcecPublicKey, notBefore, notAfter, caName, CertUtil.generateSANExt(Collections.singletonList(cn)), caKeyPair.getPublic(), caKeyPair.getPrivate(), SM2.SIGNATURE_SM3_WITH_SM2);
            skf.importCertificate(hContainer, true, sm2SIG.getEncoded());
            KeyPair encKeyPair = SM2.generateKeyPair();
            SKF_ENVELOPEDKEYBLOB skfEnvelopedkeyblob = EnvelopedUtil.assemble((BCECPrivateKey) encKeyPair.getPrivate(), (BCECPublicKey) encKeyPair.getPublic(), bcecPublicKey);
            skf.ImportECCKeyPair(hContainer, skfEnvelopedkeyblob);
            Certificate sm2ENC = CertUtil.caIssueCert(false, false, true, siteName, encKeyPair.getPublic(), notBefore, notAfter, caName, CertUtil.generateSANExt(Collections.singletonList(cn)), caKeyPair.getPublic(), caKeyPair.getPrivate(), SM2.SIGNATURE_SM3_WITH_SM2);
            skf.importCertificate(hContainer, false, sm2ENC.getEncoded());
            try (FileWriter caCertFile = new FileWriter(STORE_PATH + "ca.pem");
                 FileWriter caKeyFile = new FileWriter(STORE_PATH + "ca.key")) {
                caCertFile.write(PemUtil.cert2pem(sm2ROOT));
                caKeyFile.write(PemUtil.privateKey2pem(caKeyPair.getPrivate()));
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            if (Objects.nonNull(skf)) {
                if (Objects.nonNull(hContainer)) {
                    skf.closeContainer(hContainer);
                }
                if (Objects.nonNull(hApplication)) {
                    skf.closeApplication(hApplication);
                }
                if (Objects.nonNull(hDev)) {
                    skf.disConnectDev(hDev);
                }
            }
        }
    }

}
