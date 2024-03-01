package com.mamaliang.mmpki.gmt0016;

import com.sun.jna.Structure;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.List;

public class Struct_ECCPUBLICKEYBLOB extends Structure {

    // XCoordinate/YCoordinate的实际位数,必须是8的整数,最大512
    public int BitLen;
    public byte[] XCoordinate = new byte[64];
    public byte[] YCoordinate = new byte[64];

    public static class ByReference extends Struct_ECCPUBLICKEYBLOB implements Structure.ByReference {
    }

    public static class ByValue extends Struct_ECCPUBLICKEYBLOB implements Structure.ByValue {
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("BitLen", "XCoordinate", "YCoordinate");
    }

    public Struct_ECCPUBLICKEYBLOB() {
    }

    public Struct_ECCPUBLICKEYBLOB(int bitLength, byte[] xCoordinate, byte[] yCoordinate) {
        this.BitLen = bitLength;
        System.arraycopy(xCoordinate, 0, this.XCoordinate, 0, this.XCoordinate.length);
        System.arraycopy(yCoordinate, 0, this.YCoordinate, 0, this.YCoordinate.length);
    }

    public static Struct_ECCPUBLICKEYBLOB decode(byte[] bytes) {
        ByteBuffer all = ByteBuffer.wrap(bytes);
        byte[] bitLengthBytes = new byte[4];
        all.get(bitLengthBytes);
        int bitLength = ByteBuffer.wrap(bitLengthBytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
        if (bitLength % 8 != 0) {
            throw new IllegalArgumentException("not 0016-2012 Struct_ECCPUBLICKEYBLOB");
        }
        byte[] xBytes = new byte[64];
        all.get(xBytes);
        byte[] yBytes = new byte[64];
        all.get(yBytes);
        return new Struct_ECCPUBLICKEYBLOB(bitLength, xBytes, yBytes);
    }

    public static byte[] encode(Struct_ECCPUBLICKEYBLOB eccPublicKeyBlob) {
        ByteBuffer all = ByteBuffer.allocate(4 + 64 + 64);
        ByteBuffer bitLengthBB = ByteBuffer.allocate(Integer.BYTES);
        bitLengthBB.order(ByteOrder.LITTLE_ENDIAN);
        bitLengthBB.putInt(eccPublicKeyBlob.BitLen);
        all.put(bitLengthBB.array());
        all.put(eccPublicKeyBlob.XCoordinate);
        all.put(eccPublicKeyBlob.YCoordinate);
        return all.array();
    }

}