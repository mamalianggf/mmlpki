package com.mamaliang.mmpki.algorithm;

import com.mamaliang.mmpki.gmt0016.SKFLibraryWrapper;
import com.mamaliang.mmpki.gmt0016.Struct_ECCCIPHERBLOB;
import com.mamaliang.mmpki.gmt0016.Struct_ECCPUBLICKEYBLOB;
import com.sun.jna.Pointer;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.Objects;
import java.util.function.BiFunction;

/**
 * SM1算法处理需借助硬件，这里使用uKey
 *
 * @author gaof
 * @date 2024/10/12
 */
public class SM1 {

    /**
     * ecb模式解密
     *
     * @param dynamicLibName        动态库名称用于skf接口
     * @param existEccContainerName uKey中已存在ecc容器的名称，确保已导入加密密钥对
     * @param key                   对称密钥
     * @param encryptData           密文
     * @return 明文
     */
    public static byte[] ecbDecrypt(String dynamicLibName, String existEccContainerName, byte[] key, byte[] encryptData) {
        BiFunction<SKFLibraryWrapper, Pointer, byte[]> function = (SKFLibraryWrapper s, Pointer p) -> {
            try {
                Struct_ECCPUBLICKEYBLOB structEccPublicKeyBlob = s.exportPublicKey(p, false);
                byte[] xCoordinate = structEccPublicKeyBlob.XCoordinate;
                byte[] yCoordinate = structEccPublicKeyBlob.YCoordinate;
                BCECPublicKey encPublicKey = SM2.convert2PublicKey(xCoordinate, yCoordinate);
                byte[] encryptedSessionKey = SM2.encrypt(encPublicKey, key);
                Pointer hKey = s.importSessionKey(p, AlgorithmID.SGD_SM1_ECB, Struct_ECCCIPHERBLOB.decode(encryptedSessionKey));
                return s.decrypt(hKey, null, encryptData);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidCipherTextException e) {
                throw new RuntimeException(e);
            }
        };
        return wrap(dynamicLibName, existEccContainerName, function);
    }

    public static byte[] wrap(String dynamicLibName, String existEccContainerName, BiFunction<SKFLibraryWrapper, Pointer, byte[]> function) {
        SKFLibraryWrapper skf = null;
        Pointer hDev = null;
        Pointer hApplication = null;
        Pointer hContainer = null;
        try {
            skf = new SKFLibraryWrapper(dynamicLibName);
            List<String> devNames = skf.enumDev();
            hDev = skf.connectDev(devNames.get(0));
            List<String> applicationNames = skf.enumApplication(hDev);
            hApplication = skf.openApplication(hDev, applicationNames.get(0));
            hContainer = skf.openContainer(hApplication, existEccContainerName);
            return function.apply(skf, hApplication);
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
}
