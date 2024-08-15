package com.mamaliang.mmpki.nsagTool;

import com.mamaliang.mmpki.CertServiceTool;
import com.mamaliang.mmpki.cert.model.*;
import com.mamaliang.mmpki.cert.service.impl.DilithiumCertServiceImpl;
import com.mamaliang.mmpki.cert.service.impl.ECCCertServiceImpl;
import com.mamaliang.mmpki.cert.service.impl.RSACertServiceImpl;
import com.mamaliang.mmpki.cert.service.impl.SM2CertServiceImpl;
import com.mamaliang.mmpki.gmt0016.EnvelopedUtil;
import com.mamaliang.mmpki.model.CaWithTwoSite;
import com.mamaliang.mmpki.util.CertUtil;
import com.mamaliang.mmpki.util.PemUtil;
import com.mamaliang.mmpki.util.X500NameUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.FileWriter;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;
import java.util.Date;

/**
 * @author gaof
 * @date 2023/12/29
 */
@Disabled
public class CertTest {

    private final String storePath = "/Users/mamaliang/Workspace/mmlpki/db/";

    @Test
    void sm2SelfIssueSingleCert() throws IOException {
        CertWithPrivateKey certWithPrivateKey = CertServiceTool.selfIssueSiteCertificate(new SM2CertServiceImpl());
        try (FileWriter cert = new FileWriter(storePath + "sm2SelfIssue.pem");
             FileWriter key = new FileWriter(storePath + "sm2SelfIssue.key")) {
            cert.write(certWithPrivateKey.cert());
            key.write(certWithPrivateKey.privateKey());
        }
    }

    @Test
    void rsaSelfIssueSingleCert() throws IOException {
        CertWithPrivateKey certWithPrivateKey = CertServiceTool.selfIssueSiteCertificate(new RSACertServiceImpl());
        try (FileWriter cert = new FileWriter(storePath + "rsaSelfIssue.pem");
             FileWriter key = new FileWriter(storePath + "rsaSelfIssue.key")) {
            cert.write(certWithPrivateKey.cert());
            key.write(certWithPrivateKey.privateKey());
        }
    }

    @Test
    void eccSelfIssueSingleCert() throws IOException {
        CertWithPrivateKey certWithPrivateKey = CertServiceTool.selfIssueSiteCertificate(new ECCCertServiceImpl());
        try (FileWriter cert = new FileWriter(storePath + "eccSelfIssue.pem");
             FileWriter key = new FileWriter(storePath + "eccSelfIssue.key")) {
            cert.write(certWithPrivateKey.cert());
            key.write(certWithPrivateKey.privateKey());
        }
    }

    @Test
    void dilithiumSelfIssueSingleCert() throws IOException {
        CertWithPrivateKey certWithPrivateKey = CertServiceTool.selfIssueSiteCertificate(new DilithiumCertServiceImpl());
        try (FileWriter cert = new FileWriter(storePath + "dilithiumSelfIssue.pem");
             FileWriter key = new FileWriter(storePath + "dilithiumSelfIssue.key")) {
            cert.write(certWithPrivateKey.cert());
            key.write(certWithPrivateKey.privateKey());
        }
    }

    @Test
    void dilithiumCaSelfIssueSingleCert() throws IOException {
        String csr = """
                -----BEGIN CERTIFICATE REQUEST-----
                MIIU1jCCB+ECAQAwJDEVMBMGA1UEAwwMd3d3LnRlc3QuY29tMQswCQYDVQQGEwJD
                TjCCB7QwDQYLKwYBBAECggsHBgUDggehAOy2RViQRTgvuopF/lLCU8tomRNTXJGM
                XAt2DoWBjJ7nb9sOUt3jUoT8s+k2vlvmVkkYZVZ8SauJsk8Bkxabw0WByedvNWPH
                9pr00DEinZP84KBTxvadCgJyvSbZxWb125Ejhcg6kObaiW6iy7DEVUShQq0hAL7x
                MG9KZHF4e+myq+sICYKPsVUAGTJdPAN78VthWRLkjorZQVdTy0dTb66egm0sNG7F
                ClcTxZB6lrt0fHy5r0BMvHS2zHjEVBmuxZE2/zDZuI7BLaVqo17d/SvtLOSaVE80
                ONzlS+LAazKN7Wm/Eg2/fWLvXCwlDwSyiBy1jhFl0RxdbsCKcCB36HHChINl7q2T
                DTGAd/jJFB7vQ2cakuD1CSp8IbbI4oi6N6FxhrOnD1PcMLDv1Ka3NDDeiYKfRJdV
                k1INYI6SxXi7pguVU4msZ8DjNnVn6/WJeGbPq/Ql78txKSjyZLmEv4c1Rbx2zRLT
                9OAXBJdmuS4lPkBW/SotiPfOFl83WnmmQ/BeCz4bm8AzpH2/L4ZwwuEj0QFIKKIk
                gjO7AMp9HaVVH0o77IRAlzdHpRRt8wEQmWxJPVnEub8BrJnMw587iklxLv1Eq1mv
                YHds0QMVvwl1NHiIvMDRSZBhBD9puKjTC7s1ecI1/Tsu5u1A0nchrgJ+xAbgX3d1
                1pHsLTtFeSbKsv9aKig9Gw8EV7xLc1K6ALWrosonAYQA2u4qj+NK6pUBlPfPRlNV
                Sssm8/A5eSsmqfbTudsDh4U0lgr3qsHGZBdNM3KxidFMy0pyQs0G6vmYVVR2v2JV
                TPwj2OuTXcHE8wlcynyh21nDamSQ1b17inZdmQG/2i/fGd9/Id851vpROLVkAS2O
                8VkIUntvIyo5ijvxTIWjcW0jsGCocAZrfTCdPmQSch+9mhxyL0B6rwu/KLjexFPb
                lsI/exmbVo9J92mAr6v3Gtgw5XlP92X1HO6eJKcKL402QYrcLRuHdFkK8HBstzgl
                HDl/oZNlQBRmpnuSgGnWQawU8HvSJ/6mCxgX4qheddJwYU02u7G4tYjXtiM/8gjI
                SRhCyS3QJAzBaG6rYLDc7lNq7ZOUBOzowZtSR7nXBUxioQ1nfNdq8k6UflLkorKT
                G+dL1spSNRCVxRL31d+jyJklQFRMEIQ3R+PXrzSuSg9eoy3wcagLsSPksxntbBTY
                Oy8jpTuJR28/kmE3cWIuqj66wNZ0ZyX75yw906MyHDQJ+4cdD8QNmgfSziha6Lxb
                CEWBLex7FEuXdkQsKYkltakxnOpoO+0Pi2+qJPD0uxMXStPekh5KLMKGtURiivpq
                NK/acGNnlUAPabj7wt1GH99FV7kZYRs4ojtzuP0ULlRPHLS/4dmHl2+/Kocahedh
                V2jyGRqJpRCuSnb9cixm6ljqXPrRu73VtmSf1tbcYveN4pTiWDE4Qh/aubbdtotj
                db7H/atL5X6HCYi6ZRHI+NNKo7pq4PHVP2CQ8SsXun33+9VnKsjYNdGlj4u2QJkj
                qmCnLlGTmwCnVvhKO+guyuwIhNuVlxpREwJZF3F0LDw6y5P8UPPENdBQEJzrH3pc
                akWATLuEctmdj/xaJfaq7g7J8Ysr4LXfPPv0Y7hhzredk1DP+gYXr7UNuUcxELZt
                zO7CJcGm2Lu3IWjcJQYoINPI6Vu8W4SrB+4yIbwUN+AWXT1na+HQb9K+RcbyZkrC
                1rzjIqwVIFscs5gn/OUFkRS430q2y1kI3foFmD5PhnjipV3t/IY4LOSK9dSOLmnX
                VoCHe7CYLwmbLMvMFZwdTKoqYlFJAdRkpFfd2JY1Fv/QM918UXg4LywuhuZ/gnV2
                Je3RLkMceY9DfHpj4q+wED30i6o2gz/U+EnP6SSWKhIXdUxEFVZmx0/mf8QpJE6d
                +kAlaZa7Y/gBkeKV1vJ4OyRM4RubvPvU02el+KauBUnPWxeHPAnALhQ0ObZhU+MY
                cwflJM7LSgjJRO5CWY42GtZ3+1lO6/hmAKmfkxQAQ3Z77CjKlanVtWCmPsBFny/d
                TMPnvGT8DnekyUbDsVs0aT40ZpOKlXi2OJU62sBuEMSeskt2s4iQuaYKF7/mMjHv
                yj5cRL398DAx8Vt280nJimfCD8fu+n+oNck5yLVNR+/HqiTOmdiNC6bTsoYt7Y/r
                F40V7xPLr2li3af2BBnnOcpvVOVTrFP/GDl3XYubO9hG8ryv20S1oRWIsjd0Krfr
                ZV2G4KowosUDB6rMOKTfYKe9XMBpoe9KC3RKk/khrucJMRo0XK/kA/6LY3aZYBAp
                zG6Sp+/jLYmKgGtP/TewAF4yWs2IPF/sovmsppRhXBsT0KNRD+kG3jTx6Lw9edH2
                UKtf18FdxZpScDNBsQG25g3+DTiwznIaFEgyOgqBcyKVbMWMCiHXVkETTF/sOKva
                8F6xbz+nHsF2H9OrjiPv1RXn66foi3qBksGXeCguN2RpxMgAh35AaRZxbZhfejo4
                u9GcMbU0GmUWm4f/bAvxKL+MXsCywRwEf10uiwwfSpmOQSyhEV2d2C8IxjeKm2Fd
                RVFLJiNIRjBNrk136DMYV1DcD/WQj0xhS3Qa5Qga/p5/Gm2rcY4+QeCdCRr7b0aW
                PJtLjN2VCii1MA0GCysGAQQBAoILBwYFA4IM3gBGBi78mlFFd8ciXCPwdH0V+oUS
                1MBMdBDMbsJ9d1ru2Tud45knZZzwxor2CYHJgFLTGurhBjni3QBvoaYl/1UXJJdk
                0p7ci+mvHK/JMC1LewBhQ1ddBJ5QzDHpjrVWIjgDhQgUwV5ishYKfirjZMeFs2R8
                TpfVc+d7Axx1/2Hk2tOOSdeOXWfTSb1Py/CjbzCpIQ58FyzejM4LSDSWS0GcCprG
                V985zNpcOoQw+Ou+8AV6tAENXEwdZ56qdbpPDm3TdF/W0GiHad5sXC3Li58L5VoI
                dupGKE5m8W+8rv4c6bnPQnP8eN9uxO2Keuex/SjtLXXdByc3L9CRSqN02liO9JXd
                jTg+A6sbDJgOnY0cGY3ZZ84IhiRmO4c0As7agDnIKe8XKk3ngAWArskdITsimoN2
                hn1U/UEwz61v0xtXcuaj9ew0XMVajL+wbe4PY7xaLEChJ8ZzEo/6o9yl4txNRs5G
                VOVQ9hVkhom3xKGEThhSm7GIyElE2xViLuJa/CVt14qd6PFMdkKzJwbdntDFWr+q
                CDr0Pezl0oSZW04jXs4Gs5pmzORZ9eh6P3M2LSrchuVhOOg/uKNoLMsH902IwACU
                WSzOY7M4/zzfPGucHB+D20ZsX0WSujW1Sqmn/Ysd1f6W1F5NLBB/KR+tzqP8gaEG
                vfZmykjb/XTSliu4jT8w8aMqthOevhMySSXu7GP+nTr1WEiG/+JiOu6OoT9LOiJp
                Q1OSdgJ33bmV2b5PZZIzMa2uHuElpmqX12mXmlnOq04A01mrbgMF5JidrESmaNlF
                XVKnZuxZKQbDG0KFsj3Ve2pMQef8OGUeNdJQp490Xd2j1h+Bzm1LYbb5jwKT8vbA
                TioHuxJZsnu08YSn996NWiD5OsJpYdMLRqGIf9+WHEEtBssLjt+tz4j82gIv3t5I
                wgwFmVh0mC9exk5SK2mfd+UD5uq8GfQvX6dbvwvoilRZK2C+sSgKRkWvmPo9PHbd
                mW/GgFQunr9FGaNUfrbejvVKreWvnBJtEApYRUFtCabAkvzsRRcat0yqc0TZSxkL
                b5+H8s1s/GpNdpYIzyBZfgcVeqVssgn5XrRpLq42LodwRFoH1CiWMfStwo8knknm
                q3m+dVpZbD9pOyVnxWiYmgUXZ13v2SgRQEPRs/LNhXgtD+azcxjkzLDV7WvmIK1n
                7+H+sn+p46BNmu0ixJoSyoQKpxSBF8z64MN1TQoLEMBvUj1XlYOQ3JjIqAqChn5J
                1AAWSXH+1Zr7wxHEreGridSaMvNHSXgpvARRuCN4J8bV1xYDzCpyzMA8H5EF5w6B
                EufETUafTuySbsrwsMpie0noS98HKz7SrtHQuLG9GccDZnYRbhpZpqYdcSn2l+Gc
                KOhZmpzzopDMrVndNPSUgp5tXzNwyDw+FNUMhpsS/M1JLvlJFbgPVJEDejVtRjxx
                jHPFhO9ll8qPClSd2bCMOYljDtntlmqNhieO5fQKhnU20qPETLR2A0jXVa4VP8j5
                dcKJtoMBi9jB9x4U9nGK/3tedDPRX21KI9TBzTFyUSiDikrtdLIvOe3b8RdCUvX+
                hqwzSUlpS34KrNn3ssIwRjwI9WlJV7XYEP7+j6b6XINx9M52mTJI4UOF7sq+EKom
                vW/lxcNamesOW12e4Og4TmbUegatB7bPy2Cj8gNYlEw1G+1kHVQ8njA1X6kP/ox7
                sGR6zoX7LWNG6kWT1hrgr60qtIo4gHzmuLILmWUwlYwMH/jbGhggH+ULohEkfM7o
                DkAKK46LCzW9pKB4FTRAcZnw2tviLFNOvlDk5zrzu4yV0ZUaXZAt36hTZWKKX+4v
                VaSpQTdy8l403sjfZDmyj1QL8Fd1jAVdyjZDntPDIy2n6TrbludFxVrBwZAYG5Ut
                bnsGYY/FcQ7uyNpGxD8v0Izo35vpy6/FyWhJ0UaDnK+e79DT40xeIMEkWPd4XJM5
                U9DWqssGKcPOBsZdXd0HB5sBmNW/0Eq2L8wQ47YtgywKFWFvOzaVDG1Q72jqgFQk
                4HVtsZcS0/BwuztdM+LMNERS1QpLTQ4t+PdJs7ggDzsCj6q8zy8RR5mHxGSUNuw3
                P5zNwxeitndVNFenit53vKdBAV1YtUW98lksxnQTWuITaixDzpIYXxuXypUpCBky
                VvGkiJzATkCOeONpy2SRHmSEXukJeSKK9g99dJO2C/L2MwjBgONR6MMZ5kK/5En8
                ZChXREpjY8DwaTb3mzrFV7cK+EG63A72nBBu0a321n7sl0EJZ6mDN5AVBiOcAMHH
                6N7s03CWUhKar+sBgPW3xxrxu30eLRmIiwUbapcU1coIpz1x1O5mPB/X/CvvSgRU
                ytdiyjdtXc1jg6beEs4rpbqsEjbt6YyKvfmxB9U9S/Y3bZVRfheB0vZCUPmEJIjr
                97WK1hmOqRkevutRbt7/Ww3EC0E1RnhzWRqqNkFZMv8Ns7voCVe8GXw1uJeUmw+e
                RYfpKYZktAoI5zJkfud2sHf9irX2gvIwxMzU25af4dawOhcMSJwJ5O/1N2RGnuVr
                6gAy0Ne5KgsUZ/Nn49RE8B/eNMeXnQq6E7JP2lvfR+YI4X39zAT0LyfbI5UJzkES
                cLh+14m7nxRiVdAplZZmSzWOSqsYaexcSNrarAh42qKan9MnVurvR6Jrsn5ADdMI
                sZODvHhbbiWBJ/i3GHpO8TPhcZFUWEHnBRldOdAVZp25C7vsJDyubokJIfjDyeLo
                OtfWkhI0M30gdVMFCieEj9s0/7uOew7nh5DIDSBZmnTdWGDOlmjqYg6irrICKIzA
                4nvqEa/NF/0IZ2Pf/vHzLra6Vgv7wQfC5Uaq634xmSQvU2/wovyXZ8d0LQG0MZpw
                gRgCP39UAbq4N9E8/2s/ikR5/uiPffDosvdyCIxOESam8oEqBmzh6a4tHFzY0zYy
                kWHwM2f9jeb9hygCyFS7Rlv1eHTw6PxSW0CACM7GtmpGgFEacNZ4tNPAE1p2C7Cv
                UpmrVMf/eVM6mZtE9TKL1oE1yHIiFsDHQ701AR+XlNlMxjdONVfeXuqLZvyunFpD
                e19XsdW//ecS/BZotfXP0+i3UmusprUX9QEN/D3tWoNDKDpWmo+7tuRzBZsIq6f5
                Nor3Ebmvsk+HrCw5acfCobsN8Iw1sg87wa3AClIURAtImOSL/oC++Lh6FnJi6OJa
                NeXAciUWf5LNHEpr1PA6Ktakb4amnOpPv1UuLiibiPCGNiLI7BGy+v2kV4b6VDoN
                uYQzRR+vSF0Mwf+Qus6dNR11ec4MgWxZvh8PeH0j52a0BXxfCu3uT4fuz3gAzEQs
                eA3/kyvVyCi9vYE3itvFmsxuaRv13SGpXViWyJViA7Uzl/J0CSk2cP6XLJ5RH5Jn
                wooz6+ikLjg1UlYNFzSfqDMaOYwHLlHf8dYs1ea6zF5axJTZiNCSCweTe2VZpJMS
                zg7EOZ+LsZM7GTD+IvvD9v9eyI1nLgHjkJeznK//DVDf98ld9Xw1nLgPu4gr58L+
                vy1v52kzcX1HlTWQQJgluj7QvKEoZEJAU0SU7KMl8g9IyKUeYcNWWTIsTTnm0UZ5
                1dtg6eAUF4JqZxP/6xCjbZNBYkOVH6EZnVWLHMQeIU/uAuNq3ZPLegt7WN3RzFqQ
                qm6oi9mPkuzavxIvXOqzBiWGLjVEEJgYZtES+fFKwNTZa6Crd7TQ8yO/avCo17VI
                jKaAHBrCb13+FsdJLHTagrMIbbPoh5e/QxICAddj+Th6sA7fD6XpUbKf5zSdeJC2
                CG81Lh51LIEQKsEXDnMuRmF+0GeuAf3LSotpzQrzs8qiqlkPch8kuLRsAzNDPQQA
                MG+GeOzJQkvvIQzSaQOCj9bDNx5PElDpWhZlyfm37SO3huIFlm9dLqnW+Acxc+4A
                WzLLPE/eBn9mwL/TyGnTIzf14FkMcaVc2jK97C5TBo8AiEV6hkx8LP1lg1ihWWYg
                VyKs9+0wJalWKpzOG+qNYPuSbtk8JzDgwaw3xRBLQMSty6hca6QHHusG8xugyRO5
                zw8Vy4HaimFiieLtm/QFd2c3ohO/ujXVYnaH/LbZSp/2X5JiTyscWS27qxM+Y+U/
                aG7Pm5mZjJimQ9dCBU+XcRehQsvUv0Fh3+9+UXJi2TwKXcLO/EzUC5W7Pz/iQiSw
                NXwkzBarLNHyW6hx+5gXWLODY71ZPq27ehiAq//yhY8i+JcUOL+PzmjKfpZ11P9L
                7mpN9MJ2obY7owHgxYHGwIi35YGh8VPjqtShK+xYkwdfXb/eMo6uQq+O8gn7A2vs
                RCnQecm+y61OeKR5oXrWDFjVFGUpzjswCLmV7shDaKRqsZNTtRH6MwYCbStuC0F0
                hYyQo634ASF2kd/8PkBRW3iMrc4CMz4/SE5Ub6C04ew2VYKhrd3/TlPq7fEAAAAA
                AAAAAAkPFyMqLw==
                -----END CERTIFICATE REQUEST-----""";
        CertWithPrivateKey certWithPrivateKey = CertServiceTool.selfIssueSiteCertificate(new DilithiumCertServiceImpl());
        CaIssueCertVO caIssueCertVO = new CaIssueCertVO();
        caIssueCertVO.setCaCert(certWithPrivateKey.cert());
        caIssueCertVO.setCaPrivateKey(certWithPrivateKey.privateKey());
        caIssueCertVO.setCa(false);
        caIssueCertVO.setCsr(csr);
        caIssueCertVO.setNotBefore(new Date());
        caIssueCertVO.setNotAfter(new Date(new Date().getTime() + 10 * 360 * 24 * 60 * 60 * 1000L));
        String certPem = new DilithiumCertServiceImpl().caIssueSingleCert(caIssueCertVO);
        try (FileWriter cert = new FileWriter(storePath + "dilithiumCaIssue.pem")) {
            cert.write(certPem);
        }
    }

    /**
     * sm2 自签双证书
     * ca false
     * key 没密码
     */
    @Test
    void sm2SelfIssueDoubleSiteCertificate() throws IOException {
        DoubleCertWithDoublePrivateKey doubleCertWithDoublePrivateKey = CertServiceTool.selfIssueDoubleSiteCertificate(new SM2CertServiceImpl());
        try (FileWriter sigCert = new FileWriter(storePath + "sm2SelfIssueSig.pem");
             FileWriter sigKey = new FileWriter(storePath + "sm2SelfIssueSig.key");
             FileWriter encCert = new FileWriter(storePath + "sm2SelfIssueEnc.pem");
             FileWriter encKey = new FileWriter(storePath + "sm2SelfIssueEnc.key")) {
            sigCert.write(doubleCertWithDoublePrivateKey.sig().cert());
            sigKey.write(doubleCertWithDoublePrivateKey.sig().privateKey());
            encCert.write(doubleCertWithDoublePrivateKey.enc().cert());
            encKey.write(doubleCertWithDoublePrivateKey.enc().privateKey());
        }
    }

    /**
     * sm2 ca签发的双证书
     */
    @Test
    void sm2CaIssueDoubleCertificate() throws IOException {
        CaWithTwoSite caWithTwoSite = CertServiceTool.caIssueDoubleSiteCertificate(new SM2CertServiceImpl());
        try (FileWriter caPem = new FileWriter(storePath + "sm2rootca.pem");
             FileWriter caKey = new FileWriter(storePath + "sm2rootca.key");
             FileWriter user1PemSig = new FileWriter(storePath + "sm2CaIssueUser1Sig.pem");
             FileWriter user1KeySig = new FileWriter(storePath + "sm2CaIssueUser1Sig.key");
             FileWriter user1PemEnc = new FileWriter(storePath + "sm2CaIssueUser1Enc.pem");
             FileWriter user1KeyEnc = new FileWriter(storePath + "sm2CaIssueUser1Enc.key")) {
            caPem.write(caWithTwoSite.ca().cert());
            caKey.write(caWithTwoSite.ca().privateKey());
            user1PemSig.write(caWithTwoSite.sigSite().cert());
            user1KeySig.write(caWithTwoSite.sigSite().privateKey());
            user1PemEnc.write(caWithTwoSite.encSite().cert());
            user1KeyEnc.write(caWithTwoSite.encSite().privateKey());
        }
    }

    /**
     * sm2 ca签发的双证书(信封版本)
     */
    @Test
    void sm2CaIssueDoubleCertificateEnvelop() throws IOException {
        String path = storePath + "密钥不落地/";
        String caCommonName = "SM2ROOTCA";
        String p10 = """
                -----BEGIN CERTIFICATE REQUEST-----
                MIIBAzCBpwIBADAjMQswCQYDVQQGEwJDTjEUMBIGA1UEAwwLMTAuMC4yNDcuNzYw
                WTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATLwTOS88RE6V8wctETm54dRGw7XJM9
                P0+qns5PHScp6dcs8w/C2pnR7pLkzHrKpcsEwbPucRKFcTWxF/mvUG3YoCIwIAYJ
                KoZIhvcNAQkOMRMwETAPBgNVHREECDAGhwQKAPdMMAwGCCqBHM9VAYN1BQADSQAw
                RgIhAKQqKOTbrn681CQyS7tCIClXjMSb5AI/ogcVSCnjtwxzAiEA7nBToM8PaV9X
                wxBlZrCvXDVRRYrf3gH0+GPMHF8h+Uo=
                -----END CERTIFICATE REQUEST-----""";

        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 10 * 360 * 24 * 60 * 60 * 1000L); // 10年
        SelfIssueCertVO svo = new SelfIssueCertVO();
        X500Name caDn = X500NameUtil.generateX500Name("CN", "SH", "SH", "FUTURE", "FUTURE", caCommonName);
        svo.setSubjectDn(caDn);
        svo.setCa(false);
        svo.setNotBefore(notBefore);
        svo.setNotAfter(notAfter);
        svo.setSubjectAltNames(Collections.singletonList(caCommonName));
        CertWithPrivateKey caCertWithPrivateKey = new SM2CertServiceImpl().selfIssueSingleCert(svo);

        CaIssueCertVO cvo = new CaIssueCertVO();
        cvo.setCa(false);
        cvo.setNotBefore(notBefore);
        cvo.setNotAfter(notAfter);
        cvo.setCsr(p10);
        cvo.setCaCert(caCertWithPrivateKey.cert());
        cvo.setCaPrivateKey(caCertWithPrivateKey.privateKey());
        DoubleCertWithEnvelop doubleCertWithEnvelop = new SM2CertServiceImpl().caIssueDoubleCertWithEnvelop(cvo);
        try (FileWriter caPem = new FileWriter(path + "ca.pem");
             FileWriter caKey = new FileWriter(path + "ca.key");
             FileWriter sig = new FileWriter(path + "sm2sig.pem");
             FileWriter enc = new FileWriter(path + "sm2enc.pem");
             FileWriter envelop = new FileWriter(path + "sm2envelop.key")) {
            caPem.write(caCertWithPrivateKey.cert());
            caKey.write(caCertWithPrivateKey.privateKey());
            sig.write(doubleCertWithEnvelop.sigCert());
            enc.write(doubleCertWithEnvelop.encCert());
            envelop.write(doubleCertWithEnvelop.envelop());
        }
    }

    @Test
    public void test1() throws Exception {
        String encPrivateKeyPem = """
                -----BEGIN PRIVATE KEY-----
                MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgnHMsugjNdINpHznj
                6Hmwe1dpZA4ecfKhKgW0dpZVgeGhRANCAATHPM9VI51UWq0WBCGMBa3R63ngP4ts
                6c6jjzN5/WzX/6b5heOeLTAFyIF6ufd0e47F8nT2bPuy61HHHvLtuQX2
                -----END PRIVATE KEY-----""";
        PrivateKey encPrivateKey = PemUtil.pem2privateKey(encPrivateKeyPem);

        String encCertPem = """
                -----BEGIN CERTIFICATE-----
                MIIDczCCAxegAwIBAgIIdMEAQARXlU4wDAYIKoEcz1UBg3UFADBSMQswCQYDVQQG
                EwJDTjEvMC0GA1UECgwmWmhlamlhbmcgRGlnaXRhbCBDZXJ0aWZpY2F0ZSBBdXRo
                b3JpdHkxEjAQBgNVBAMMCVpKQ0EgT0NBMTAeFw0yNDA4MTMxNjAwMDBaFw0yNTA4
                MTQxNTU5NTlaMCQxCzAJBgNVBAYTAkNOMRUwEwYDVQQDDAwxMC41NC4zOC4yMDQw
                WTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATHPM9VI51UWq0WBCGMBa3R63ngP4ts
                6c6jjzN5/WzX/6b5heOeLTAFyIF6ufd0e47F8nT2bPuy61HHHvLtuQX2o4ICATCC
                Af0wDAYDVR0TBAUwAwEBADAOBgNVHQ8BAf8EBAMCADAwFwYDVR0RBBAwDoIMMTAu
                NTQuMzguMjA0MCsGCSsGAQQBgjcUAgQeHhwAUwBtAGEAcgB0AGMAYQByAGQATABv
                AGcAbwBuMB8GA1UdIwQYMBaAFKfTsSSQIB09tFTuSzcoUpGuLGoiMIGxBgNVHR8E
                gakwgaYwgaOggaCggZ2GgZpsZGFwOi8vbGRhcC56amNhLmNvbS5jbi9DTj1aSkNB
                IE9DQTFncm91cDcyODQsQ049WkpDQSBPQ0ExLCBPVT1DUkxEaXN0cmlidXRlUG9p
                bnRzLCBvPXpqY2E/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVj
                dGNsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIGiBggrBgEFBQcBAQSBlTCBkjCB
                jwYIKwYBBQUHMAKGgYJsZGFwOi8vbGRhcC56amNhLmNvbS5jbi9DTj1aSkNBIE9D
                QTEsQ049WkpDQSBPQ0ExLCBPVT1jQUNlcnRpZmljYXRlcywgbz16amNhP2NBQ2Vy
                dGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5
                MB0GA1UdDgQWBBRrAmmtyFNAjIpT7etS7jhxbYVtPzAMBggqgRzPVQGDdQUAA0gA
                MEUCIQDzF4FgeP/59lyxtTY2tEUr/nSzeEXU5PZheDstRRI1KwIgU4XQ+uKJ/KkR
                zhHzFb3YluUUuqnPrZy8oQsR7fNSnzU=
                -----END CERTIFICATE-----""";
        Certificate encCert = PemUtil.pem2Cert(encCertPem);
        PublicKey encPublicKey = CertUtil.extraPublicKey(encCert);

        String sigCertPem= """
                -----BEGIN CERTIFICATE-----
                MIIDbjCCAxKgAwIBAgIIdMEAqwRXlU8wDAYIKoEcz1UBg3UFADBSMQswCQYDVQQG
                EwJDTjEvMC0GA1UECgwmWmhlamlhbmcgRGlnaXRhbCBDZXJ0aWZpY2F0ZSBBdXRo
                b3JpdHkxEjAQBgNVBAMMCVpKQ0EgT0NBMTAeFw0yNDA4MTMxNjAwMDBaFw0yNTA4
                MTQxNTU5NTlaMCQxCzAJBgNVBAYTAkNOMRUwEwYDVQQDDAwxMC41NC4zOC4yMDQw
                WTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAARvdqOfmBh5gomhAB62UIfZNkT8t/G8
                BQSwfIe4dnRb9Sf1J4maRySCkLrvHD808c7bbaSpj10datZX47cdr02no4IB/DCC
                AfgwDAYDVR0TBAUwAwEBADATBgNVHSUEDDAKBggrBgEFBQcDATAOBgNVHQ8BAf8E
                BAMCAMAwEQYJYIZIAYb4QgEBBAQDAgBAMBcGA1UdEQQQMA6CDDEwLjU0LjM4LjIw
                NDAfBgNVHSMEGDAWgBSn07EkkCAdPbRU7ks3KFKRrixqIjCBsQYDVR0fBIGpMIGm
                MIGjoIGgoIGdhoGabGRhcDovL2xkYXAuempjYS5jb20uY24vQ049WkpDQSBPQ0Ex
                Z3JvdXA3Mjg0LENOPVpKQ0EgT0NBMSwgT1U9Q1JMRGlzdHJpYnV0ZVBvaW50cywg
                bz16amNhP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RjbGFz
                cz1jUkxEaXN0cmlidXRpb25Qb2ludDCBogYIKwYBBQUHAQEEgZUwgZIwgY8GCCsG
                AQUFBzAChoGCbGRhcDovL2xkYXAuempjYS5jb20uY24vQ049WkpDQSBPQ0ExLENO
                PVpKQ0EgT0NBMSwgT1U9Y0FDZXJ0aWZpY2F0ZXMsIG89empjYT9jQUNlcnRpZmlj
                YXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTAdBgNV
                HQ4EFgQUTCb4AJgPldn/xx7aDKvYY3la98MwDAYIKoEcz1UBg3UFAANIADBFAiBJ
                hkDhyCA94W1p5AsNLwLA2Yv8LZne6G5CO6YRPkG7AgIhANep2AuNZ9PSEeW5VCOS
                Vx/kaxE2Y8rjeBJaIND+uMRP
                -----END CERTIFICATE-----""";
        Certificate sigCert = PemUtil.pem2Cert(sigCertPem);
        PublicKey sigPublicKey = CertUtil.extraPublicKey(sigCert);

        String envelop = EnvelopedUtil.assembleFront((BCECPrivateKey) encPrivateKey, (BCECPublicKey) encPublicKey, (BCECPublicKey) sigPublicKey);
        try (FileWriter assembleEnvelop = new FileWriter(storePath + "assembleEnvelop.pem")) {
            assembleEnvelop.write(envelop);
        }
    }

}
