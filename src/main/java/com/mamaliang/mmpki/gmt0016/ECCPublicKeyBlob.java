package com.mamaliang.mmpki.gmt0016;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * ECC 公钥数据结构
 *
 * @author gaof
 * @date 2023/10/31
 */
public class ECCPublicKeyBlob {

    // ECC 算法 X 坐标的最大长度
    public static final int ECC_MAX_XCOORDINATE_BITS_LEN = 512;

    // ECC 算法 Y 坐标的最大长度
    public static final int ECC_MAX_YCOORDINATE_BITS_LEN = 512;

    // 模数的实际位长度,必须是8的倍数
    private final int bitLength;

    // 曲线上点的 X 坐标
    private final byte[] xCoordinate = new byte[32];

    // 曲线上点的 Y 坐标
    private final byte[] yCoordinate = new byte[32];

    public ECCPublicKeyBlob(int bitLength, byte[] xCoordinate, byte[] yCoordinate) {
        this.bitLength = bitLength;
        System.arraycopy(xCoordinate, 0, this.xCoordinate, 0, this.xCoordinate.length);
        System.arraycopy(yCoordinate, 0, this.yCoordinate, 0, this.yCoordinate.length);
    }

    public int getBitLength() {
        return bitLength;
    }

    public byte[] getxCoordinate() {
        return xCoordinate;
    }

    public byte[] getyCoordinate() {
        return yCoordinate;
    }

    public static ECCPublicKeyBlob decode(byte[] bytes) {
        ByteBuffer all = ByteBuffer.wrap(bytes);

        byte[] bitLengthBytes = new byte[4];
        all.get(bitLengthBytes);
        int bitLength = ByteBuffer.wrap(bitLengthBytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if (bitLength % 8 != 0) {
            throw new IllegalArgumentException("not 0016-2012 Struct_ECCPUBLICKEYBLOB");
        }

        all.position(all.position() + 32);// 跳过32字节
        byte[] xBytes = new byte[32];
        all.get(xBytes);

        all.position(all.position() + 32);// 跳过32字节
        byte[] yBytes = new byte[32];
        all.get(yBytes);

        return new ECCPublicKeyBlob(bitLength, xBytes, yBytes);
    }

    public static byte[] encode(ECCPublicKeyBlob eccPublicKeyBlob) {

        ByteBuffer all = ByteBuffer.allocate(4 + (32 + 32) + (32 + 32));

        ByteBuffer bitLengthBB = ByteBuffer.allocate(Integer.BYTES);
        bitLengthBB.order(ByteOrder.LITTLE_ENDIAN);
        bitLengthBB.putInt(eccPublicKeyBlob.getBitLength());
        all.put(bitLengthBB.array());

        all.position(all.position() + 32);// 跳过32字节
        all.put(eccPublicKeyBlob.getxCoordinate());

        all.position(all.position() + 32);// 跳过32字节
        all.put(eccPublicKeyBlob.getyCoordinate());

        return all.array();

    }
}
