# todo
1. 看整套逻辑能不能更进一步共用代码,通过将某种算法的所有参数组成一个参数集,作为泛型
2. 为什么使用PEMParse.TYPE_EC_PRIVATE_KEY解析会失败:encoded key spec not recognized: null
3. SKFLibrary的LongByReference全部换成IntByReference


# 疑问
1. ECCCipherBlob的X和Y在规范上定义的是ECC_MAX_XCOORDINATE_BITS_LEN / 8,那么字节长度应是64,但是实际测试发现,前32位均是0,只有后32位有值,不清楚为什么
2. ECCCipherBlob的字节分布是否存在多种情况
3. cbEncryptedPrivKey为什么只取后32个字节
4. 导入加密密钥信封时会报0x0A00001A HASH值不相等 这是为什么