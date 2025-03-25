package com.mamaliang.mmpki.gmt0016;

import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

/**
 * @author gaof
 * @date 2024/4/11
 */
public class Struct_BLOCKCIPHERPARAM extends Structure {

    public byte[] IVS = new byte[32];
    public int IVLen;
    // 填充方式，0 表示不填充，1 表示按照PKCS#5 方式进行填充
    public int PaddingType;
    public int FeedBitLen;


    public static class ByReference extends Struct_BLOCKCIPHERPARAM implements Structure.ByReference {
    }

    public static class ByValue extends Struct_BLOCKCIPHERPARAM implements Structure.ByValue {
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("IVS", "IVLen", "PaddingType", "FeedBitLen");
    }

}
