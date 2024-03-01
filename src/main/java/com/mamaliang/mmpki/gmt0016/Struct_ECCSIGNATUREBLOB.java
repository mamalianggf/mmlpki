package com.mamaliang.mmpki.gmt0016;

import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

public class Struct_ECCSIGNATUREBLOB extends Structure {

    public byte[] r = new byte[64];
    public byte[] s = new byte[64];

    public static class ByReference extends Struct_ECCSIGNATUREBLOB implements Structure.ByReference {
    }

    public static class ByValue extends Struct_ECCSIGNATUREBLOB implements Structure.ByValue {
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("r", "s");
    }


}