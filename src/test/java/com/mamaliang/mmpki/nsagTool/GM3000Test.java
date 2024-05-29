package com.mamaliang.mmpki.nsagTool;

import com.mamaliang.mmpki.algorithm.AlgorithmID;
import com.mamaliang.mmpki.algorithm.SM2;
import com.mamaliang.mmpki.algorithm.SM4;
import com.mamaliang.mmpki.gmt0016.*;
import com.mamaliang.mmpki.util.CertUtil;
import com.mamaliang.mmpki.util.X500NameUtil;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.nio.ByteBuffer;
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

    @Test
    void testListContainer() {
        SKFLibraryWrapper skf = null;
        Pointer hDev = null;
        Pointer hApplication = null;
        try {
            skf = new SKFLibraryWrapper("gm3000.1.0");
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

    @Test
    void testCreateContainer() {
        SKFLibraryWrapper skf = null;
        Pointer hDev = null;
        Pointer hApplication = null;
        try {
            skf = new SKFLibraryWrapper("gm3000.1.0");
            List<String> devNames = skf.enumDev();
            hDev = skf.connectDev(devNames.get(0));
            List<String> applicationNames = skf.enumApplication(hDev);
            hApplication = skf.openApplication(hDev, applicationNames.get(0));
            skf.enumContainer(hApplication);
            // 辉哥的key,目前只知道用户pin码是12345678,管理员pin码和设备认证码都不知道
            skf.verifyPIN(hApplication, 1, "12345678");
            skf.createContainer(hApplication, "niubi");
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

    @Test
    void testDeleteContainer() {
        SKFLibraryWrapper skf = null;
        Pointer hDev = null;
        Pointer hApplication = null;
        try {
            skf = new SKFLibraryWrapper("gm3000.1.0");
            List<String> devNames = skf.enumDev();
            hDev = skf.connectDev(devNames.get(0));
            List<String> applicationNames = skf.enumApplication(hDev);
            hApplication = skf.openApplication(hDev, applicationNames.get(0));
            skf.enumContainer(hApplication);
            // 辉哥的key,目前只知道用户pin码是12345678,管理员pin码和设备认证码都不知道
            skf.verifyPIN(hApplication, 1, "12345678");
            skf.deleteContainer(hApplication, "niubi");
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

    @Test
    void testGenerateECCKeyPair() {
        SKFLibraryWrapper skf = null;
        Pointer hDev = null;
        Pointer hApplication = null;
        Pointer hContainer = null;
        try {
            skf = new SKFLibraryWrapper("gm3000.1.0");
            List<String> devNames = skf.enumDev();
            hDev = skf.connectDev(devNames.get(0));
            List<String> applicationNames = skf.enumApplication(hDev);
            hApplication = skf.openApplication(hDev, applicationNames.get(0));
            String containerName = "niubi";
            hContainer = skf.openContainer(hApplication, containerName);
            skf.verifyPIN(hApplication, 1, "12345678");
            skf.genECCKeyPair(hContainer);
        } finally {
            if (Objects.nonNull(skf)) {
                if (Objects.nonNull(hApplication)) {
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


    @Test
    void testGenerateCertificateAndImport() {
        SKFLibraryWrapper skf = null;
        Pointer hDev = null;
        Pointer hApplication = null;
        Pointer hContainer = null;
        try {
            skf = new SKFLibraryWrapper("gm3000.1.0");
            List<String> devNames = skf.enumDev();
            hDev = skf.connectDev(devNames.get(0));
            List<String> applicationNames = skf.enumApplication(hDev);
            hApplication = skf.openApplication(hDev, applicationNames.get(0));
            String containerName = "niubi";
            hContainer = skf.openContainer(hApplication, containerName);

            skf.verifyPIN(hApplication, 1, "12345678");
            Struct_ECCPUBLICKEYBLOB eccPublicKeyBlob = skf.exportPublicKey(hContainer, true);
            BCECPublicKey bcecPublicKey = SM2.convert2PublicKey(eccPublicKeyBlob.XCoordinate, eccPublicKeyBlob.YCoordinate);

            // ca cert
            X500Name caName = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "SM2ROOT");
            Date notBefore = new Date();
            Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年
            KeyPair caKeyPair = SM2.generateKeyPair();
            Certificate sm2ROOT = CertUtil.selfIssueCert(true, false, false, caName, notBefore, notAfter, Collections.singletonList("SM2ROOT"), caKeyPair, SM2.SIGNATURE_SM3_WITH_SM2);
            // sig cert and enc key pair and enc cert
            X500Name siteName = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", "SM2TEST");
            Certificate sm2SIG = CertUtil.caIssueCert(false, true, false, siteName, bcecPublicKey, notBefore, notAfter, caName, CertUtil.generateSANExt(Collections.singletonList("SM2TEST")), caKeyPair.getPublic(), caKeyPair.getPrivate(), SM2.SIGNATURE_SM3_WITH_SM2);
            skf.importCertificate(hContainer, true, sm2SIG.getEncoded());
            KeyPair encKeyPair = SM2.generateKeyPair();
            SKF_ENVELOPEDKEYBLOB skfEnvelopedkeyblob = EnvelopedUtil.assembleBackend((BCECPrivateKey) encKeyPair.getPrivate(), (BCECPublicKey) encKeyPair.getPublic(), bcecPublicKey);
            skf.ImportECCKeyPair(hContainer, skfEnvelopedkeyblob);
            Certificate sm2ENC = CertUtil.caIssueCert(false, false, true, siteName, encKeyPair.getPublic(), notBefore, notAfter, caName, CertUtil.generateSANExt(Collections.singletonList("SM2TEST")), caKeyPair.getPublic(), caKeyPair.getPrivate(), SM2.SIGNATURE_SM3_WITH_SM2);
            skf.importCertificate(hContainer, true, sm2ENC.getEncoded());

        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            if (Objects.nonNull(skf)) {
                if (Objects.nonNull(hApplication)) {
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

    /**
     * 要用硬件生成会话密钥,并用skf函数对称加密,所以没有用EnvelopedUtil中的方法
     */
//    private SKF_ENVELOPEDKEYBLOB assembleByHardWare(SKFLibraryWrapper skf, Pointer phContainer, BCECPrivateKey encPrivateKey, BCECPublicKey encPublicKey, BCECPublicKey signPublicKey) throws Exception {
//        // 加密私钥中提取 d
//        BigInteger d = encPrivateKey.getD();
//        byte[] dBytes = d.toByteArray();
//        if (dBytes[0] == 0x00) {// d一定是正数
//            dBytes = deleteTheFirstByte(dBytes);
//        }
//        // 从硬件中获取会话密钥,会话密钥要用指定的公钥进行加密,所以需要提供公钥
//        byte[] x = encPublicKey.getQ().getAffineXCoord().getEncoded();
//        x = completeByteArray(x, 64);
//        byte[] y = encPublicKey.getQ().getAffineYCoord().getEncoded();
//        y = completeByteArray(y, 64);
//        Struct_ECCPUBLICKEYBLOB encPublicKeyBlob = new Struct_ECCPUBLICKEYBLOB(256, x, y);
//        Struct_ECCCIPHERBLOB ecccipherblob = new Struct_ECCCIPHERBLOB();
//        PointerByReference phSessionKey = new PointerByReference();
//        skf.eccExportSessionKey(phContainer, encPublicKeyBlob, ecccipherblob,phSessionKey);
//        // 对称密钥 加密 d
////        byte[] cbEncryptedPrivKey = SM4.ecbEncrypt(symmKey, dBytes);
//        skf.
//
//        // 不足64bit,补全至64bit
//        cbEncryptedPrivKey = completeByteArray(cbEncryptedPrivKey, 64);
//        // 签名公钥加密加密私钥
//        byte[] symmKeyBytes = symmKey.getEncoded();
//        byte[] encryptedSymmKeyBytes = SM2.encrypt(signPublicKey, symmKeyBytes);
//
//        byte[] x = encPublicKey.getQ().getAffineXCoord().getEncoded();
//        x = completeByteArray(x, 64);
//        byte[] y = encPublicKey.getQ().getAffineYCoord().getEncoded();
//        y = completeByteArray(y, 64);
//        Struct_ECCPUBLICKEYBLOB eccPublicKeyBlob = new Struct_ECCPUBLICKEYBLOB(256, x, y);
//
//        if (encryptedSymmKeyBytes[0] == 0x04) {
//            encryptedSymmKeyBytes = deleteTheFirstByte(encryptedSymmKeyBytes);
//        }
//        ByteBuffer bb = ByteBuffer.wrap(encryptedSymmKeyBytes);
//        byte[] c1x = new byte[32];
//        byte[] c1y = new byte[32];
//        byte[] c3 = new byte[32];
//        bb.get(c1x);
//        bb.get(c1y);
//        bb.get(c3);
//        byte[] c2 = new byte[bb.remaining()];
//        bb.get(c2);
//        c1x = completeByteArray(c1x, 64);
//        c1y = completeByteArray(c1y, 64);
//        Struct_ECCCIPHERBLOB eccCipherBlob = new Struct_ECCCIPHERBLOB(c1x, c1y, c3, c2.length, c2);
//
//        return new SKF_ENVELOPEDKEYBLOB(SKF_ENVELOPEDKEYBLOB.VERSION, AlgorithmID.SGD_SM4_ECB, 256, cbEncryptedPrivKey, eccPublicKeyBlob, eccCipherBlob);
//    }

    private static byte[] deleteTheFirstByte(byte[] bytes) {
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        bb.position(1);
        byte[] temp = new byte[bb.remaining()];
        bb.get(temp);
        return temp;
    }

    /**
     * 补全位数至goal,补前面
     */
    private static byte[] completeByteArray(byte[] bytes, int goal) {
        if (bytes.length < goal) {
            byte[] temp = new byte[goal];
            System.arraycopy(bytes, 0, temp, temp.length - bytes.length, bytes.length);
            return temp;
        }
        return bytes;
    }

}
