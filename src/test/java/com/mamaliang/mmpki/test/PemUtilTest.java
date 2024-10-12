package com.mamaliang.mmpki.test;

import com.mamaliang.mmpki.util.PemUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author gaof
 * @date 2024/10/12
 */
class PemUtilTest {

    @Test
    void pem2privateKey() {
        String opensslECKey = """
                -----BEGIN EC PRIVATE KEY-----
                MHcCAQEEINrRmJakALfM5uf0L1dRb9CL6NWwjxMM966/aZPbLsAVoAoGCCqGSM49
                AwEHoUQDQgAEHsOsc1S9w6FtQK7zj05K1Sp5Hp8PwQOrww8MqCqm2RsmeSm7TsPL
                F0yxgjuCRu3YzactYJvUg1q4u52merfQTA==
                -----END EC PRIVATE KEY-----
                """;
        String pkcs8ECKey = """
                -----BEGIN PRIVATE KEY-----
                MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2tGYlqQAt8zm5/Qv
                V1Fv0Ivo1bCPEwz3rr9pk9suwBWhRANCAAQew6xzVL3DoW1ArvOPTkrVKnkenw/B
                A6vDDwyoKqbZGyZ5KbtOw8sXTLGCO4JG7djNpy1gm9SDWri7naZ6t9BM
                -----END PRIVATE KEY-----
                """;
        Assertions.assertDoesNotThrow(()->PemUtil.pem2privateKey(opensslECKey));
        Assertions.assertDoesNotThrow(()->PemUtil.pem2privateKey(pkcs8ECKey));
    }
}