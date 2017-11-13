package cz.crcs.ectester.standalone.test;

import cz.crcs.ectester.common.test.TestException;
import cz.crcs.ectester.common.test.Testable;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;

public class KeyGenerationTestable implements Testable {

    private KeyPair kp;
    private KeyPairGenerator kpg;
    private int keysize;
    private AlgorithmParameterSpec spec;
    private boolean hasRun;
    private boolean error = false;
    private boolean ok;

    public KeyGenerationTestable(KeyPairGenerator kpg, int keysize) {
        this.kpg = kpg;
        this.keysize = keysize;
    }

    public KeyGenerationTestable(KeyPairGenerator kpg, AlgorithmParameterSpec spec) {
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
            } else {
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
