package com.mamaliang.mmpki.gmt0016;

import com.sun.jna.Library;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

/**
 * @author gaof
 * @date 2024/2/6
 */
public interface SKFLibrary extends Library {

    // ----- 设备函数 ----- //
    int SKF_EnumDev(int bPresent, byte[] szNameList, IntByReference pulSize);

    int SKF_ConnectDev(String szName, PointerByReference phDev);

    int SKF_DisConnectDev(Pointer hDev);

    // ----- 应用函数 ----- //

    int SKF_EnumApplication(Pointer hDev, byte[] szAppNameList, IntByReference pulSize);

    //int SKF_CreateApplication(Pointer hDev, String szAppName, String szAdminPin, int dwAdminPinRetryCount, String szUserPin, int dwUserPinRetryCount, int dwCreateFileRights, PointerByReference phApplication);

    int SKF_OpenApplication(Pointer hDev, String szAppName, PointerByReference phApplication);

    int SKF_VerifyPIN(Pointer hApplication, int ulPINType, String szPIN, IntByReference pulRetryCount);

    int SKF_CloseApplication(Pointer hApplication);

    // ----- 容器函数 ----- //
    int SKF_EnumContainer(Pointer hApplication, byte[] szContainerNameList, IntByReference pulSize);

    int SKF_CreateContainer(Pointer hApplication, String szContainerName, PointerByReference phContainer);

    int SKF_DeleteContainer(Pointer hApplication, String szContainerName);

    int SKF_OpenContainer(Pointer hApplication, String szContainerName, PointerByReference phContainer);

    int SKF_CloseContainer(Pointer hContainer);

    int SKF_GetContainerType(Pointer hContainer, IntByReference pulContainerType);

    int SKF_GenECCKeyPair(Pointer hContainer, int ulAlgId, Struct_ECCPUBLICKEYBLOB pBlob);

    int SKF_ImportECCKeyPair(Pointer hContainer, byte[] pEnvelopedKeyBlob);

    int SKF_ExportPublicKey(Pointer hContainer, int bSignFlag, Struct_ECCPUBLICKEYBLOB pBlob, IntByReference pulBlobLen);

    int SKF_ImportCertificate(Pointer hContainer, int bSignFlag, byte[] pbCert, int ulCertLen);

    int SKF_ExportCertificate(Pointer hContainer, boolean bSignFlag, byte[] pbCert, IntByReference pulCertLen);

    // ----- 密钥函数 ----- //
    //    int SKF_ECCSignData(Pointer hContainer, byte[] pbData, int ulDataLen, Struct_ECCSIGNATUREBLOB pSignature);
    //
    //    int SKF_ECCVerify(Pointer hDev, Struct_ECCPUBLICKEYBLOB pECCPubKeyBlob, Struct_SM3BLOB pbData, int ulDataLen, Struct_ECCSIGNATUREBLOB pSignature);
    //
    //    int SKF_ECCExportSessionKey(Pointer hContainer, int ulAlgId, Struct_ECCPUBLICKEYBLOB pPubKey, Struct_ECCCIPHERBLOB pData, PointerByReference phSessionKey);

    int SKF_ImportSessionKey(Pointer hContainer, int ulAlgId, byte[] pbWrapedData, int ulWrapedLen, PointerByReference phKey);

    //    int SKF_EncryptInit(Pointer hKey, Struct_BLOCKCIPHERPARAM EncryptParam);
    //
    //    int SKF_Encrypt(Pointer hKey, byte[] pbData, int ulDataLen, byte[] pbEncryptedData, IntByReference pulEncryptedLen);

    int SKF_DecryptInit(Pointer hKey, Struct_BLOCKCIPHERPARAM.ByValue decryptParam);

    int SKF_Decrypt(Pointer hKey, byte[] pbEncryptedData, int ulEncryptedLen, byte[] pbData, IntByReference pulDataLen);

    //    int SKF_CloseHandle(Pointer hkey);

}
