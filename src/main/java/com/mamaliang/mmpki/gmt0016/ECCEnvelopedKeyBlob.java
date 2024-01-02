package com.mamaliang.mmpki.gmt0016;

import com.mamaliang.mmpki.algorithm.AlgorithmID;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * 0016-2012 SKF_ENVELOPEDKEYBLOB
 * 未采用ASN.1编码
 *
 * @author gaof
 * @date 2023/10/31
 */
public class ECCEnvelopedKeyBlob {

    public static final int VERSION = 0x01;

    // 版本号,本版本为1
    private final int version;

    // 对称算法标识,限定 ECB 模式
    private final int ulSymmAlgId;

    // 加密密钥对的密钥长度
    private final int ulBits;

    // 对称算法加密的加密私钥,加密私钥的原文为 ECCPRIVATEKEYBLOB 结构中的 PrivateKey,其有效长度为原文的 (ulBits +7) /8
    private final byte[] cbEncryptedPrivKey = new byte[64];

    // 加密密钥对的公钥
    private final ECCPublicKeyBlob pubKey;

    // 用保护公钥加密过的对称密钥密文
    private final ECCCipherBlob eccCipherBlob;

    public ECCEnvelopedKeyBlob(int version, int ulSymmAlgId, int ulBits, byte[] cbEncryptedPrivKey, ECCPublicKeyBlob pubKey, ECCCipherBlob eccCipherBlob) {
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

    public int getVersion() {
        return version;
    }

    public int getUlSymmAlgId() {
        return ulSymmAlgId;
    }

    public int getUlBitS() {
        return ulBits;
    }

    public byte[] getCbEncryptedPrivKey() {
        return cbEncryptedPrivKey;
    }

    public ECCPublicKeyBlob getPubKey() {
        return pubKey;
    }

    public ECCCipherBlob getEccCipherBlob() {
        return eccCipherBlob;
    }

    public static ECCEnvelopedKeyBlob decode(byte[] eccEnvelopedKeyBlobBytes) {
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

        //all.position(all.position() + 32);// 跳过32字节
        byte[] cbEncryptedPrivKeyBytes = new byte[64];
        all.get(cbEncryptedPrivKeyBytes);

        byte[] pubKeyBytes = new byte[132];
        all.get(pubKeyBytes);
        ECCPublicKeyBlob eccPublicKeyBlob = ECCPublicKeyBlob.decode(pubKeyBytes);

        byte[] eccCipherBlobBytes = new byte[all.remaining()];
        all.get(eccCipherBlobBytes);
        ECCCipherBlob eccCipherBlob = ECCCipherBlob.decode(eccCipherBlobBytes);

        return new ECCEnvelopedKeyBlob(version, ulSymmAlgId, ulBits, cbEncryptedPrivKeyBytes, eccPublicKeyBlob, eccCipherBlob);

    }

    public static byte[] encode(ECCEnvelopedKeyBlob eccEnvelopedKeyBlob) {

        byte[] pubKeyBytes = ECCPublicKeyBlob.encode(eccEnvelopedKeyBlob.getPubKey());
        byte[] eccCipherBlobBytes = ECCCipherBlob.encode(eccEnvelopedKeyBlob.getEccCipherBlob());

        ByteBuffer all = ByteBuffer.allocate(4 + 4 + 4 + 64 + pubKeyBytes.length + eccCipherBlobBytes.length);

        ByteBuffer versionBB = ByteBuffer.allocate(Integer.BYTES);
        versionBB.order(ByteOrder.LITTLE_ENDIAN);
        versionBB.putInt(eccEnvelopedKeyBlob.getVersion());
        all.put(versionBB.array());

        ByteBuffer ulSymmAlgIdBB = ByteBuffer.allocate(Integer.BYTES);
        ulSymmAlgIdBB.order(ByteOrder.LITTLE_ENDIAN);
        ulSymmAlgIdBB.putInt(eccEnvelopedKeyBlob.getUlSymmAlgId());
        all.put(ulSymmAlgIdBB.array());

        ByteBuffer ulBitsBB = ByteBuffer.allocate(Integer.BYTES);
        ulBitsBB.order(ByteOrder.LITTLE_ENDIAN);
        ulBitsBB.putInt(eccEnvelopedKeyBlob.getUlBitS());
        all.put(ulBitsBB.array());

        //all.position(all.position() + 32);// 跳过32字节
        all.put(eccEnvelopedKeyBlob.cbEncryptedPrivKey);

        all.put(pubKeyBytes);

        all.put(eccCipherBlobBytes);

        return all.array();

    }
}
