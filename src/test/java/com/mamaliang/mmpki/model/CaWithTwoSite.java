package com.mamaliang.mmpki.model;

import com.mamaliang.mmpki.cert.model.CertWithPrivateKey;

/**
 * @author gaof
 * @date 2024/7/26
 */
public record CaWithTwoSite(CertWithPrivateKey ca, CertWithPrivateKey sigSite, CertWithPrivateKey encSite) {
}
