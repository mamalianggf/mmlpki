package com.mamaliang.mmpki.gmt0016;

import com.sun.jna.Structure;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.List;

/**
 * ECC 密文数据结构
 * C = C1 || C3 || C2
 * C1 -> ( X , Y )
 * C3 -> hash
 * C2 -> cipher
 *
 * @author gaof
 * @date 2024/3/3
 */
public class Struct_ECCCIPHERBLOB extends Structure {

    public byte[] xCoordinate = new byte[64];
    public byte[] yCoordinate = new byte[64];
    public byte[] hash = new byte[32];
    // 密文数据长度
    public int cipherLen;
    // 密文数据，长度为 cipherLen 决定
    public byte[] cipher = new byte[32];

    public static class ByReference extends Struct_ECCCIPHERBLOB implements Structure.ByReference {
    }

    public static class ByValue extends Struct_ECCCIPHERBLOB implements Structure.ByValue {
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("xCoordinate", "yCoordinate", "hash", "cipherLen", "cipher");
    }

    public Struct_ECCCIPHERBLOB() {
    }

    public Struct_ECCCIPHERBLOB(byte[] xCoordinate, byte[] yCoordinate, byte[] hash, int cipherLen, byte[] cipher) {
        System.arraycopy(xCoordinate, 0, this.xCoordinate, 0, this.xCoordinate.length);
        System.arraycopy(yCoordinate, 0, this.yCoordinate, 0, this.yCoordinate.length);
        System.arraycopy(hash, 0, this.hash, 0, this.hash.length);
        this.cipherLen = cipherLen;
        System.arraycopy(cipher, 0, this.cipher, 0, cipherLen);
    }

    public static Struct_ECCCIPHERBLOB decode(byte[] bytes) {
        ByteBuffer all = ByteBuffer.wrap(bytes);
        if (bytes.length <= (64 * 2 + 32 + 4)) {
            throw new IllegalArgumentException("not 0016-2012 Struct_ECCCIPHERBLOB");
        }
        byte[] xBytes = new byte[64]; // 前32字节为空
        all.get(xBytes);
        byte[] yBytes = new byte[64]; // 前32字节为空
        all.get(yBytes);
        byte[] hashBytes = new byte[32];
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
        return new Struct_ECCCIPHERBLOB(xBytes, yBytes, hashBytes, cipherLen, cipherBytes);
    }

    public static byte[] encode(Struct_ECCCIPHERBLOB eccCipherBlob) {
        ByteBuffer all = ByteBuffer.allocate(64 * 2 + 32 + 4 + eccCipherBlob.cipherLen);
        all.put(eccCipherBlob.xCoordinate);
        all.put(eccCipherBlob.yCoordinate);
        all.put(eccCipherBlob.hash);
        if (eccCipherBlob.cipherLen > eccCipherBlob.cipher.length) {
            throw new IllegalArgumentException("not 0016-2012 Struct_ECCCIPHERBLOB");
        }
        ByteBuffer cipherBB = ByteBuffer.allocate(Integer.BYTES);
        cipherBB.order(ByteOrder.LITTLE_ENDIAN);
        cipherBB.putInt(eccCipherBlob.cipherLen);
        all.put(cipherBB.array());
        all.put(eccCipherBlob.cipher, 0, eccCipherBlob.cipherLen);
        return all.array();
    }

}
