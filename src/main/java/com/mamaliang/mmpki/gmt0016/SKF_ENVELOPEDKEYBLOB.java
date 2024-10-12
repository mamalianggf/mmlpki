package com.mamaliang.mmpki.gmt0016;

import com.sun.jna.Structure;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * @author gaof
 * @date 2024/3/3
 */
public class SKF_ENVELOPEDKEYBLOB extends Structure {

    public static final int VERSION = 0x01;

    // 版本号,本版本为1
    public int version;
    // 对称算法标识,限定 ECB 模式
    public int ulSymmAlgId;
    // 加密密钥对的密钥长度
    public int ulBits;
    // 对称算法加密的加密私钥,加密私钥的原文为 ECCPRIVATEKEYBLOB 结构中的 PrivateKey,其有效长度为原文的 (ulBits +7) /8
    public final byte[] cbEncryptedPrivKey = new byte[64];
    // 加密密钥对的公钥
    public Struct_ECCPUBLICKEYBLOB pubKey;
    // 用保护公钥加密过的对称密钥密文
    public Struct_ECCCIPHERBLOB eccCipherBlob;

    public static class ByReference extends SKF_ENVELOPEDKEYBLOB implements Structure.ByReference {
    }

    public static class ByValue extends SKF_ENVELOPEDKEYBLOB implements Structure.ByValue {
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("version", "ulSymmAlgId", "ulBits", "cbEncryptedPrivKey", "pubKey", "eccCipherBlob");
    }


    public SKF_ENVELOPEDKEYBLOB() {
    }

    public SKF_ENVELOPEDKEYBLOB(int version, int ulSymmAlgId, int ulBits, byte[] cbEncryptedPrivKey, Struct_ECCPUBLICKEYBLOB pubKey, Struct_ECCCIPHERBLOB eccCipherBlob) {
        this.version = version;
        this.ulSymmAlgId = ulSymmAlgId;
        this.ulBits = ulBits;
        if (cbEncryptedPrivKey.length != 64) {
            throw new IllegalArgumentException("cbEncryptedPrivKey should be 64 bits");
        }
        System.arraycopy(cbEncryptedPrivKey, 0, this.cbEncryptedPrivKey, 0, this.cbEncryptedPrivKey.length);
        this.pubKey = pubKey;
        this.eccCipherBlob = eccCipherBlob;
    }

    public static SKF_ENVELOPEDKEYBLOB decode(byte[] eccEnvelopedKeyBlobBytes) {
        // 默认大端
        ByteBuffer all = ByteBuffer.wrap(eccEnvelopedKeyBlobBytes);
        byte[] versionBytes = new byte[4];
        all.get(versionBytes);
        int version = ByteBuffer.wrap(versionBytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if (version != VERSION) {
            throw new IllegalArgumentException("not 0016-2012 SKF_ENVELOPEDKEYBLOB");
        }
        byte[] ulSymmAlgIdBytes = new byte[4];
        all.get(ulSymmAlgIdBytes);
        int ulSymmAlgId = ByteBuffer.wrap(ulSymmAlgIdBytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
        byte[] ulBitsBytes = new byte[4];
        all.get(ulBitsBytes);
        int ulBits = ByteBuffer.wrap(ulBitsBytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if (ulBits != 256) {
            throw new IllegalArgumentException("only sm2 key length");
        }
        byte[] cbEncryptedPrivKeyBytes = new byte[64];
        all.get(cbEncryptedPrivKeyBytes);
        byte[] pubKeyBytes = new byte[132];
        all.get(pubKeyBytes);
        Struct_ECCPUBLICKEYBLOB eccPublicKeyBlob = Struct_ECCPUBLICKEYBLOB.decode(pubKeyBytes);
        byte[] eccCipherBlobBytes = new byte[all.remaining()];
        all.get(eccCipherBlobBytes);
        Struct_ECCCIPHERBLOB eccCipherBlob = Struct_ECCCIPHERBLOB.decode(eccCipherBlobBytes);
        return new SKF_ENVELOPEDKEYBLOB(version, ulSymmAlgId, ulBits, cbEncryptedPrivKeyBytes, eccPublicKeyBlob, eccCipherBlob);
    }

    public static byte[] encode(SKF_ENVELOPEDKEYBLOB envelopedkeyblob) {
        byte[] pubKeyBytes = Struct_ECCPUBLICKEYBLOB.encode(envelopedkeyblob.pubKey);
        byte[] eccCipherBlobBytes = Struct_ECCCIPHERBLOB.encode(envelopedkeyblob.eccCipherBlob);
        ByteBuffer all = ByteBuffer.allocate(4 + 4 + 4 + 64 + pubKeyBytes.length + eccCipherBlobBytes.length);
        ByteBuffer versionBB = ByteBuffer.allocate(Integer.BYTES);
        versionBB.order(ByteOrder.LITTLE_ENDIAN);
        versionBB.putInt(envelopedkeyblob.version);
        all.put(versionBB.array());
        ByteBuffer ulSymmAlgIdBB = ByteBuffer.allocate(Integer.BYTES);
        ulSymmAlgIdBB.order(ByteOrder.LITTLE_ENDIAN);
        ulSymmAlgIdBB.putInt(envelopedkeyblob.ulSymmAlgId);
        all.put(ulSymmAlgIdBB.array());
        ByteBuffer ulBitsBB = ByteBuffer.allocate(Integer.BYTES);
        ulBitsBB.order(ByteOrder.LITTLE_ENDIAN);
        ulBitsBB.putInt(envelopedkeyblob.ulBits);
        all.put(ulBitsBB.array());
        all.put(envelopedkeyblob.cbEncryptedPrivKey);
        all.put(pubKeyBytes);
        all.put(eccCipherBlobBytes);
        return all.array();
    }

    public static String toBase64String(SKF_ENVELOPEDKEYBLOB envelopedKeyBlob) {
        return new String(Base64.getEncoder().encode(encode(envelopedKeyBlob)), StandardCharsets.UTF_8);
    }

    public static SKF_ENVELOPEDKEYBLOB fromBase64String(String base64String) {
        byte[] eccEnvelopedKeyBlobBytes = Base64.getDecoder().decode(base64String.getBytes(StandardCharsets.UTF_8));
        return SKF_ENVELOPEDKEYBLOB.decode(eccEnvelopedKeyBlobBytes);
    }
}
