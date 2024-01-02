package com.mamaliang.mmpki.gmt0016;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * ECC 密文数据结构
 * C = C1 || C3 || C2
 * C1 -> ( X , Y )
 * C3 -> hash
 * C2 -> cipher
 *
 * @author gaof
 * @date 2023/10/31
 */
public class ECCCipherBlob {

    // ECC 算法 X 坐标的最大长度
    public static final int ECC_MAX_XCOORDINATE_BITS_LEN = 512;
    // ECC 算法 Y 坐标的最大长度
    public static final int ECC_MAX_YCOORDINATE_BITS_LEN = 512;
    // SM2密钥长度
    public static final int SM2_BIT_LENGTH = 256;
    public static final int SM2_MAX_LEN = ((SM2_BIT_LENGTH + 7) / 8);

    // 曲线上点的 X 坐标
    private final byte[] xCoordinate = new byte[SM2_MAX_LEN];

    // 曲线上点的 Y 坐标
    private final byte[] yCoordinate = new byte[SM2_MAX_LEN];

    // 明文的杂凑值。
    private final byte[] hash = new byte[SM2_MAX_LEN];

    // 密文数据长度
    private final int cipherLen;

    // 密文数据，长度为 cipherLen 决定
    private final byte[] cipher = new byte[SM2_MAX_LEN];

    public ECCCipherBlob(byte[] xCoordinate, byte[] yCoordinate, byte[] hash, int cipherLen, byte[] cipher) {
        System.arraycopy(xCoordinate, 0, this.xCoordinate, 0, this.xCoordinate.length);
        System.arraycopy(yCoordinate, 0, this.yCoordinate, 0, this.yCoordinate.length);
        System.arraycopy(hash, 0, this.hash, 0, this.hash.length);
        this.cipherLen = cipherLen;
        System.arraycopy(cipher, 0, this.cipher, 0, cipherLen);
    }

    public byte[] getxCoordinate() {
        return xCoordinate;
    }

    public byte[] getyCoordinate() {
        return yCoordinate;
    }

    public byte[] getHash() {
        return hash;
    }

    public int getCipherLen() {
        return cipherLen;
    }

    public byte[] getCipher() {
        return cipher;
    }

    public static ECCCipherBlob decode(byte[] bytes) {

        ByteBuffer all = ByteBuffer.wrap(bytes);

        if (bytes.length < SM2_MAX_LEN * 4 + 4) {
            // 这是加密机引擎返回的SM2CipherResult格式数据
            all.position(1/*跳过1字节编码类型*/);
            int cipherLen = bytes.length - 1 - SM2_MAX_LEN - SM2_MAX_LEN - SM2_MAX_LEN;
            byte[] xCoordinate = new byte[SM2_MAX_LEN];
            all.get(xCoordinate);
            byte[] yCoordinate = new byte[SM2_MAX_LEN];
            all.get(yCoordinate);
            byte[] cipher = new byte[SM2_MAX_LEN];
            all.get(cipher, 0, cipherLen);
            byte[] hash = new byte[SM2_MAX_LEN];
            all.get(hash);
            return new ECCCipherBlob(xCoordinate, yCoordinate, hash, cipherLen, cipher);
        } else if (bytes.length == SM2_MAX_LEN * 4 + 4) {
            // 这是加密机生成的原始密文数据
            all.position(0);
            int cipherLen = all.getInt();
            byte[] xCoordinate = new byte[SM2_MAX_LEN];
            all.get(xCoordinate);
            byte[] yCoordinate = new byte[SM2_MAX_LEN];
            all.get(yCoordinate);
            byte[] cipher = new byte[SM2_MAX_LEN];
            all.get(cipher, 0, cipherLen);
            byte[] hash = new byte[SM2_MAX_LEN];
            all.get(hash);
            return new ECCCipherBlob(xCoordinate, yCoordinate, hash, cipherLen, cipher);
        } else {
            // 这是国密介质生成的数据
            all.position(all.position() + SM2_MAX_LEN); // 跳过32字节
            byte[] xBytes = new byte[SM2_MAX_LEN]; // 读取32字节
            all.get(xBytes);

            all.position(all.position() + SM2_MAX_LEN); // 跳过32字节
            byte[] yBytes = new byte[SM2_MAX_LEN]; // 读取32字节
            all.get(yBytes);

            byte[] hashBytes = new byte[SM2_MAX_LEN];

            all.get(hashBytes);

            byte[] cipherLenBytes = new byte[4];
            all.get(cipherLenBytes);
            int cipherLen = ByteBuffer.wrap(cipherLenBytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
            int remaining = all.remaining();
            if (cipherLen > remaining) {
                throw new IllegalArgumentException("not 0016-2012 Struct_ECCCIPHERBLOB");
            }

            byte[] cipherBytes = new byte[cipherLen];
            all.get(cipherBytes);
            return new ECCCipherBlob(xBytes, yBytes, hashBytes, cipherLen, cipherBytes);
        }
    }


    public static byte[] encode(ECCCipherBlob eccCipherBlob) {
        // 按国密介质生成的数据
        ByteBuffer all = ByteBuffer.allocate((SM2_MAX_LEN * 2) + (SM2_MAX_LEN * 2) + SM2_MAX_LEN + 4 + eccCipherBlob.getCipherLen());

        all.position(all.position() + SM2_MAX_LEN);// 跳过32字节
        all.put(eccCipherBlob.getxCoordinate());

        all.position(all.position() + SM2_MAX_LEN);// 跳过32字节
        all.put(eccCipherBlob.getyCoordinate());

        all.put(eccCipherBlob.getHash());

        if (eccCipherBlob.getCipherLen() > eccCipherBlob.getCipher().length) {
            throw new IllegalArgumentException("not 0016-2012 Struct_ECCCIPHERBLOB");
        }
        ByteBuffer cipherBB = ByteBuffer.allocate(Integer.BYTES);
        cipherBB.order(ByteOrder.LITTLE_ENDIAN);
        cipherBB.putInt(eccCipherBlob.getCipherLen());
        all.put(cipherBB.array());

        all.put(eccCipherBlob.getCipher(), 0, eccCipherBlob.getCipherLen());

        return all.array();
    }
}
