package com.mamaliang.mmpki.crl.controller;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.cert.X509CRL;

/**
 * @author gaof
 * @date 2023/11/29
 */
@RequestMapping(path = "/crls", produces = "application/pkix-crl")
public class CRLDistributionPointController {

    @RequestMapping(path = "/{name}")
    public X509CRL getCRL(@PathVariable("name") String crlName) {
        // todo
        X509CRL crl = null;
        return crl;
    }

}
