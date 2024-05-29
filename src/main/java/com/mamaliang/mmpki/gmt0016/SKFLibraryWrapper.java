package com.mamaliang.mmpki.gmt0016;

import com.mamaliang.mmpki.algorithm.AlgorithmID;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author gaof
 * @date 2024/2/6
 */
@Slf4j
public class SKFLibraryWrapper {

    private final SKFLibrary uKey;

    public SKFLibraryWrapper(String dynamicLibName) {
        this.uKey = Native.load(dynamicLibName, SKFLibrary.class);
    }

    // ----- 设备函数 ----- //
    public List<String> enumDev() {
        IntByReference pulSizeOut = new IntByReference();
        checkError(uKey.SKF_EnumDev(1, null, pulSizeOut));
        int szNameListSize = pulSizeOut.getPointer().getInt(0);
        if (szNameListSize == 0) {
            throw new RuntimeException("未获取到设备名");
        }
        byte[] szNameListBbr = new byte[szNameListSize];
        IntByReference pulSizeIn = new IntByReference(szNameListSize);
        checkError(uKey.SKF_EnumDev(1, szNameListBbr, pulSizeIn));
        List<String> devNames = convertCString(szNameListBbr);
        log.info("找到设备:{}", devNames);
        return devNames;
    }

    public Pointer connectDev(String szName) {
        PointerByReference phDev = new PointerByReference();
        checkError(uKey.SKF_ConnectDev(szName, phDev));
        log.info("连接设备:{}", szName);
        return phDev.getValue();
    }

    public void disConnectDev(Pointer hDev) {
        checkError(uKey.SKF_DisConnectDev(hDev));
        log.info("断开设备");
    }

    // ----- 应用函数 ----- //
    public List<String> enumApplication(Pointer hDev) {
        IntByReference pulSizeOut = new IntByReference();
        checkError(uKey.SKF_EnumApplication(hDev, null, pulSizeOut));
        int szAppNameListSize = pulSizeOut.getPointer().getInt(0);
        if (szAppNameListSize == 0) {
            throw new RuntimeException("未获取到应用名");
        }
        byte[] szAppNameListBbr = new byte[szAppNameListSize];
        IntByReference pulSizeIn = new IntByReference(szAppNameListSize);
        checkError(uKey.SKF_EnumApplication(hDev, szAppNameListBbr, pulSizeIn));
        List<String> applicationNames = convertCString(szAppNameListBbr);
        log.info("找到应用:{}", applicationNames);
        return applicationNames;
    }

    public Pointer openApplication(Pointer hDev, String szAppName) {
        PointerByReference phApplication = new PointerByReference();
        checkError(uKey.SKF_OpenApplication(hDev, szAppName, phApplication));
        log.info("打开应用:{}", szAppName);
        return phApplication.getValue();
    }

    /**
     * type: 0 管理员 ; 1 用户
     */
    public void verifyPIN(Pointer hApplication, int type, String pin) {
        IntByReference pulRetryCount = new IntByReference();
        int ret = uKey.SKF_VerifyPIN(hApplication, type, pin, pulRetryCount);
        String s = type == 0 ? "管理员" : "用户";
        if (ret == 0) {
            log.info("校验{}pin码成功,获取到{}权限", s, s);
        } else {
            log.error("校验{}pin码失败,剩余{}次机会", s, pulRetryCount.getValue());
        }
    }

    public void closeApplication(Pointer hApplication) {
        checkError(uKey.SKF_CloseApplication(hApplication));
        log.info("关闭应用");
    }

    // ----- 容器函数 ----- //
    public List<String> enumContainer(Pointer hApplication) {
        IntByReference pulSizeOut = new IntByReference();
        checkError(uKey.SKF_EnumContainer(hApplication, null, pulSizeOut));
        int szContainerNameListSize = pulSizeOut.getPointer().getInt(0);
        if (szContainerNameListSize == 0) {
            throw new RuntimeException("未获取到容器名");
        }
        IntByReference pulSizeIn = new IntByReference(szContainerNameListSize);
        byte[] bytes = new byte[szContainerNameListSize];
        checkError(uKey.SKF_EnumContainer(hApplication, bytes, pulSizeIn));
        List<String> containerNames = convertCString(bytes);
        log.info("找到容器:{}", containerNames);
        return containerNames;
    }

    public void createContainer(Pointer hApplication, String szContainerName) {
        PointerByReference phContainer = new PointerByReference();
        checkError(uKey.SKF_CreateContainer(hApplication, szContainerName, phContainer));
        log.info("创建容器:{}成功", szContainerName);
        // closeContainer(phContainer.getPointer()); gm3000上测试会报无效的句柄
    }

    public void deleteContainer(Pointer hApplication, String szContainerName) {
        checkError(uKey.SKF_DeleteContainer(hApplication, szContainerName));
        log.info("删除容器:{}成功", szContainerName);
    }

    public Pointer openContainer(Pointer hApplication, String containerName) {
        PointerByReference phContainer = new PointerByReference();
        checkError(uKey.SKF_OpenContainer(hApplication, containerName, phContainer));
        log.info("打开容器:{}", containerName);
        return phContainer.getValue();
    }

    public void closeContainer(Pointer hContainer) {
        checkError(uKey.SKF_CloseContainer(hContainer));
        log.info("关闭容器");
    }

    /**
     * 0表示未定、尚未分配类型或者空容器,1表示RSA容器,2表示SM2容器。
     */
    public void getContainerType(Pointer hContainer) {
        IntByReference lbf = new IntByReference();
        checkError(uKey.SKF_GetContainerType(hContainer, lbf));
        String type = switch ((int) lbf.getValue()) {
            case 1 -> "RSA";
            case 2 -> "SM2";
            default -> "未定、尚未分配类型或者空容器";
        };
        log.info("容器类型为:{}", type);
    }

    public Struct_ECCPUBLICKEYBLOB genECCKeyPair(Pointer hContainer) {
        Struct_ECCPUBLICKEYBLOB.ByReference bf = new Struct_ECCPUBLICKEYBLOB.ByReference();
        checkError(uKey.SKF_GenECCKeyPair(hContainer, AlgorithmID.SGD_SM2_1, bf));
        log.info("生成ECC密钥对完成");
        return bf;
    }

    public void ImportECCKeyPair(Pointer hContainer, SKF_ENVELOPEDKEYBLOB pEnvelopedKeyBlob) {
        checkError(uKey.SKF_ImportECCKeyPair(hContainer, pEnvelopedKeyBlob));
        log.info("导入ECC加密密钥对完成");
    }

    public Struct_ECCPUBLICKEYBLOB exportPublicKey(Pointer hContainer, boolean sign) {
        int flag = sign ? 1 : 0;
        IntByReference pulSizeOut = new IntByReference();
        checkError(uKey.SKF_ExportPublicKey(hContainer, flag, null, pulSizeOut));
        int length = pulSizeOut.getPointer().getInt(0);
        if (length == 0) {
            throw new RuntimeException("未能导出" + (sign ? "签名" : "加密") + "公钥");
        }
        IntByReference pulSizeIn = new IntByReference(length);
        Struct_ECCPUBLICKEYBLOB eccPublicKeyBlob = new Struct_ECCPUBLICKEYBLOB();
        checkError(uKey.SKF_ExportPublicKey(hContainer, flag, eccPublicKeyBlob, pulSizeIn));
        log.info("导出{}公钥成功", sign ? "签名" : "加密");
        return eccPublicKeyBlob;
    }

    public void importCertificate(Pointer hContainer, boolean sign, byte[] cert) {
        int flag = sign ? 1 : 0;
        checkError(uKey.SKF_ImportCertificate(hContainer, flag, cert, cert.length));
        log.info("导入{}证书成功", sign ? "签名" : "加密");
    }

    // ----- 密钥函数 ----- //

    /**
     * plain应是待签名数据的杂凑值
     */
    public Struct_ECCSIGNATUREBLOB eccSignData(Pointer hContainer, byte[] plain) {
        Struct_ECCSIGNATUREBLOB.ByReference byReference = new Struct_ECCSIGNATUREBLOB.ByReference();
        checkError(uKey.SKF_ECCSignData(hContainer, plain, plain.length, byReference));
        log.info("签名成功");
        return byReference;
    }

    public void eccExportSessionKey(Pointer hContainer, Struct_ECCPUBLICKEYBLOB pPubKey, Struct_ECCCIPHERBLOB pData, PointerByReference phSessionKey) {
        checkError(uKey.SKF_ECCExportSessionKey(hContainer, AlgorithmID.SGD_SM4_CBC, pPubKey, pData, phSessionKey));
        log.info("导出会话密钥成功");
    }

    private static void checkError(int ret) {
        if (ret != 0) {
            String hexNumber = String.format("0x%08X", ret);
            throw new RuntimeException("operated failed,return code:" + hexNumber + ",mean:" + errorCode.get(hexNumber));
        }
    }

    private static List<String> convertCString(byte[] bytes) {
        return Arrays.asList(new String(bytes).replace("\0", " ").trim().split(" "));
    }

    private static final Map<String, String> errorCode = new HashMap<>();

    static {
        errorCode.put("0x00000000", "成功");
        errorCode.put("0x0A000001", "失败");
        errorCode.put("0x0A000002", "异常错误");
        errorCode.put("0x0A000003", "不支持的服务");
        errorCode.put("0x04000004", "文件操作错误");
        errorCode.put("0x0A000005", "无效的句柄");
        errorCode.put("0x0A000006", "无效的参数");
        errorCode.put("0x0A000007", "读文件错误");
        errorCode.put("0x0A000008", "写文件错误");
        errorCode.put("0x0A000009", "名称长度错误");
        errorCode.put("0x0A00000A", "密钥用途错误");
        errorCode.put("0x0A00000B", "模的长度错误");
        errorCode.put("0x0A00000C", "未初始化");
        errorCode.put("0x0A00000D", "对象错误");
        errorCode.put("0x0A00000E", "内存错误");
        errorCode.put("0x0A00000F", "超时");
        errorCode.put("0x0A000010", "输入数据长度错误");
        errorCode.put("0x0A000011", "输入数据错误");
        errorCode.put("0x0A000012", "生成随机数错误");
        errorCode.put("0х0A000013", "HASH对象错");
        errorCode.put("0x0A000014", "HASH运算错误");
        errorCode.put("0x0A000015", "产生RSA密钥错");
        errorCode.put("0x0A000016", "RSA密钥模长错误");
        errorCode.put("0x0A000017", "CSP服务导入公钥错误");
        errorCode.put("0x0A000018", "RSA加密错误");
        errorCode.put("0x0A000019", "RSA解密错误");
        errorCode.put("0x0A00001A", "HASH值不相等");
        errorCode.put("0x0A00001B", "密钥未发现");
        errorCode.put("0x0A00001C", "证书未发现");
        errorCode.put("0x0A00001D", "对象未导出");
        errorCode.put("0x0A00001E", "解密时做补丁错误");
        errorCode.put("0x0A00001F", "MAC长度错误");
        errorCode.put("0x0A000020", "缓冲区不足");
        errorCode.put("0x0A000021", "密钥类型错误");
        errorCode.put("0x0A000022", "无事件错误");
        errorCode.put("0x0A000023", "设备已移除");
        errorCode.put("0x0A000024", "PIN不正确");
        errorCode.put("0x0A000025", "PIN被锁死");
        errorCode.put("0x0A000026", "PIN无效");
        errorCode.put("0x0A000027", "PIN长度错误");
        errorCode.put("0x0A000028", "用户已经登录");
        errorCode.put("0x0A000029", "没有初始化用户口令");
        errorCode.put("0x0A00002A", "PIN类型错误");
        errorCode.put("0x0A00002B", "应用名称无效");
        errorCode.put("0x0A00002C", "应用已经存在");
        errorCode.put("0x0A00002D", "用户没有登录");
        errorCode.put("0x0A00002E", "应用不存在");
        errorCode.put("0x0A00002F", "文件已经存在");
        errorCode.put("0x0A000030", "空间不足");
        errorCode.put("0x0A000031", "文件不存在");
        errorCode.put("0x0A000032", "已达到最大可管理容器数");
        // 以下是GM3000的添加的错误码
        errorCode.put("0x0B000033", "安全状态不满足");
        errorCode.put("0x0B000034", "指针移到超过文件长度");
        errorCode.put("0x0B000035", "容器不存在");
        errorCode.put("0x0B000036", "容器已存在");
        errorCode.put("0x0B000037", "设备认证锁定");
        errorCode.put("0x0B000038", "ECC加密错误");
    }

}
