package cz.crcs.ectester.standalone.test;

import cz.crcs.ectester.common.test.TestException;
import cz.crcs.ectester.common.test.Testable;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECParameterSpec;

public class KeyGenerationTestable implements Testable {

    private KeyPair kp;
    private KeyPairGenerator kpg;
    private int keysize = 0;
    private ECParameterSpec spec = null;
    private boolean hasRun;
    private boolean error = false;
    private boolean ok;

    public KeyGenerationTestable(KeyPairGenerator kpg) {
        this.kpg = kpg;
    }

    public KeyGenerationTestable(KeyPairGenerator kpg, int keysize) {
        this.kpg = kpg;
        this.keysize = keysize;
    }

    public KeyGenerationTestable(KeyPairGenerator kpg, ECParameterSpec spec) {
        this.kpg = kpg;
        this.spec = spec;
    }

    public KeyPair getKeyPair() {
        return kp;
    }

    @Override
    public boolean hasRun() {
        return hasRun;
    }

    @Override
    public void run() throws TestException {
        try {
            if (spec != null) {
                kpg.initialize(spec);
            } else if (keysize != 0) {
                kpg.initialize(keysize);
            }
        } catch (InvalidAlgorithmParameterException e) {
            hasRun = true;
            ok = false;
            return;
        }
        kp = kpg.genKeyPair();
        hasRun = true;
        ok = true;
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
