package com.mamaliang.mmpki.algorithm;

import com.mamaliang.mmpki.gmt0016.SKFUtil;
import com.mamaliang.mmpki.gmt0016.Struct_ECCCIPHERBLOB;
import com.mamaliang.mmpki.gmt0016.Struct_ECCPUBLICKEYBLOB;
import com.mamaliang.mmpki.util.PropertiesUtil;
import com.sun.jna.Pointer;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * SM1算法处理需借助硬件，这里使用uKey
 *
 * @author gaof
 * @date 2024/10/12
 */

public class SM1 {

    private static final String devName;
    private static final String applicationName;
    private static final String containerName;

    static {
        // 检查usbKey种是否存在对应的容器
        String containerPath = PropertiesUtil.getString("usbKey.sm1.container.path");
        String[] pathArray = containerPath.split("/");
        if (SKFUtil.isExistContainer(pathArray[0], pathArray[1], pathArray[2])) {
            throw new RuntimeException("usbKey.sm1.container.path配置错误");
        }
        devName = pathArray[0];
        applicationName = pathArray[1];
        containerName = pathArray[2];
    }

    /**
     * ecb模式解密
     *
     * @param key         对称密钥
     * @param encryptData 密文
     * @return 明文
     */
    public static byte[] ecbDecrypt(byte[] key, byte[] encryptData) {
        try {
            Struct_ECCPUBLICKEYBLOB structEccPublicKeyBlob = SKFUtil.exportPublicKey(devName, applicationName, containerName, false);
            byte[] xCoordinate = structEccPublicKeyBlob.XCoordinate;
            byte[] yCoordinate = structEccPublicKeyBlob.YCoordinate;
            BCECPublicKey encPublicKey = SM2.convert2PublicKey(xCoordinate, yCoordinate);
            byte[] encryptedSessionKey = SM2.encrypt(encPublicKey, key);
            Pointer hKey = SKFUtil.importSessionKey(devName, applicationName, containerName, AlgorithmID.SGD_SM1_ECB, Struct_ECCCIPHERBLOB.decode(encryptedSessionKey));
            // todo param不清楚如何定义
            return SKFUtil.decrypt(hKey, null, encryptData);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
    }
}
