package com.mamaliang.mmpki.cert.model;

/**
 * @author gaof
 * @date 2024/7/4
 */
public record DoubleCertWithEnvelop(String sigCert, String encCert, String envelop) {
}
