package cz.crcs.ectester.standalone;

import cz.crcs.ectester.standalone.consts.KeyAgreementIdent;
import cz.crcs.ectester.standalone.consts.KeyPairGeneratorIdent;
import cz.crcs.ectester.standalone.consts.SignatureIdent;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyAgreement;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Signature;

import static org.junit.jupiter.api.Assertions.*;

public class IdentTests {

    Provider bc = new BouncyCastleProvider();

    @Test
    void kaIdents() throws NoSuchAlgorithmException {
        for (KeyAgreementIdent keyAgreementIdent : KeyAgreementIdent.list()) {
            assertNotNull(keyAgreementIdent.getBaseAlgo());
        }
        KeyAgreementIdent ecdh = KeyAgreementIdent.get("ECDH");
        assertNotNull(ecdh);
        KeyAgreement instance = ecdh.getInstance(bc);
        assertNotNull(instance);
    }

    @Test
    void kpgIdents() throws NoSuchAlgorithmException {
        assertFalse(KeyPairGeneratorIdent.list().isEmpty());
        KeyPairGeneratorIdent kpg = KeyPairGeneratorIdent.get("ECDH");
        assertNotNull(kpg);
        KeyPairGenerator instance = kpg.getInstance(bc);
        assertNotNull(instance);
    }

    @Test
    void sigIdents() throws NoSuchAlgorithmException {
        assertFalse(SignatureIdent.list().isEmpty());
        SignatureIdent ecdsa = SignatureIdent.get("NONEwithECDSA");
        assertNotNull(ecdsa);
        Signature instance = ecdsa.getInstance(bc);
        assertNotNull(instance);
    }
}
