package cz.crcs.ectester.standalone.test;

import cz.crcs.ectester.common.test.TestException;
import cz.crcs.ectester.common.test.Testable;

import javax.crypto.KeyAgreement;
import java.security.InvalidKeyException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class KeyAgreementTestable implements Testable {
    private KeyAgreement ka;
    private ECPrivateKey privateKey;
    private ECPublicKey publicKey;
    private byte[] secret;
    private boolean hasRun;
    private boolean error = false;
    private boolean ok;

    public KeyAgreementTestable(KeyAgreement ka, ECPrivateKey privateKey, ECPublicKey publicKey) {
        this.ka = ka;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public byte[] getSecret() {
        if (!hasRun) {
            return null;
        }
        return secret;
    }

    @Override
    public boolean hasRun() {
        return hasRun;
    }

    @Override
    public void run() throws TestException {
        try {
            ka.init(privateKey);
        } catch (InvalidKeyException ikex) {
            throw new TestException(ikex);
        }

        try {
            ka.doPhase(publicKey, true);
        } catch (InvalidKeyException ikex) {
            throw new TestException(ikex);
        } catch (IllegalStateException isex) {
            ok = false;
            hasRun = true;
            return;
        }

        try {
            secret = ka.generateSecret();
        } catch (IllegalStateException isex) {
            ok = false;
            hasRun = true;
            return;
        }
        ok = true;
        hasRun = true;
    }

    @Override
    public boolean ok() {
        return ok;
    }

    @Override
    public boolean error() {
        return error;
    }
}
