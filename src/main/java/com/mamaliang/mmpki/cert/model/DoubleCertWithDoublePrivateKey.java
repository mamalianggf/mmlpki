package com.mamaliang.mmpki.cert.model;

/**
 * @author gaof
 * @date 2024/7/4
 */
public record DoubleCertWithDoublePrivateKey(String sigCert, String sigPrivateKey, String encCert, String encPrivateKey) {
}
