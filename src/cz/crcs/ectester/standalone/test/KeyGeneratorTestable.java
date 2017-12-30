package cz.crcs.ectester.standalone.test;

import cz.crcs.ectester.common.test.BaseTestable;
import cz.crcs.ectester.common.test.TestException;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECParameterSpec;

public class KeyGeneratorTestable extends BaseTestable {
    private KeyPair kp;
    private KeyPairGenerator kpg;
    private int keysize = 0;
    private ECParameterSpec spec = null;

    public KeyGeneratorTestable(KeyPairGenerator kpg) {
        this.kpg = kpg;
    }

    public KeyGeneratorTestable(KeyPairGenerator kpg, int keysize) {
        this.kpg = kpg;
        this.keysize = keysize;
    }

    public KeyGeneratorTestable(KeyPairGenerator kpg, ECParameterSpec spec) {
        this.kpg = kpg;
        this.spec = spec;
    }

    public KeyPairGenerator getKpg() {
        return kpg;
    }

    public KeyPair getKeyPair() {
        return kp;
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
}
