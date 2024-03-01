package com.mamaliang.mmpki.algorithm;

/**
 * GBT_33560-2017 信息安全技术密码应用标识规范
 *
 * @author gaof
 * @date 2023/10/31
 */
public class AlgorithmID {

    public static final int SGD_SM1_ECB = 0x00000101;       //SM1算法ECB加密模式
    public static final int SGD_SM1_CBC = 0x00000102;       //SM1算法CBC加密模式
    public static final int SGD_SM1_CFB = 0x00000104;       //SM1算法CFB加密模式
    public static final int SGD_SM1_OFB = 0x00000108;       //SM1算法OFB加密模式
    public static final int SGD_SM1_MAC = 0x00000110;       //SM1算法MAC运算
    public static final int SGD_SM2_1 = 0x00020100;         //椭圆曲线签名算法
    public static final int SGD_SM2_2 = 0x00020200;         //椭圆曲线密钥交换协议
    public static final int SGD_SM2_3 = 0x00020400;         //椭圆曲线加密算法
    public static final int SGD_SSF33_ECB = 0x00000201;     //SSF33算法ECB加密模式
    public static final int SGD_SSF33_CBC = 0x00000202;     //SSF33算法CBC加密模式
    public static final int SGD_SSF33_CFB = 0x00000204;     //SSF33算法CFB加密模式
    public static final int SGD_SSF33_OFB = 0x00000208;     //SSF33算法OFB加密模式
    public static final int SGD_SSF33_MAC = 0x00000210;     //SSF33算法MAC运算
    public static final int SGD_SM4_ECB = 0x00000401;       //SMS4算法ECB加密模式
    public static final int SGD_SM4_CBC = 0x00000402;       //SMS4算法CBC加密模式
    public static final int SGD_SM4_CFB = 0x00000404;       //SMS4算法CFB加密模式
    public static final int SGD_SM4_OFB = 0x00000408;       //SMS4算法OFB加密模式
    public static final int SGD_SM4_MAC = 0x00000410;       //SMS4算法MAC运算

}