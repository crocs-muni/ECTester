package cz.crcs.ectester.reader;

import cz.crcs.ectester.standalone.consts.KeyAgreementIdent;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
public class IdentTests {
    @Test
    void kaIdents() {
        for (KeyAgreementIdent keyAgreementIdent : KeyAgreementIdent.list()) {
            assertNotNull(keyAgreementIdent.getBaseAlgo());
        }
    }
}
