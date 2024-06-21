package cz.crcs.ectester.standalone.test.base;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class KeyGeneratorTestable extends StandaloneTestable<KeyGeneratorTestable.KeyGeneratorStage> {
    private KeyPair kp;
    private final KeyPairGenerator kpg;
    private int keysize = 0;
    private AlgorithmParameterSpec spec = null;

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

    public KeyGeneratorTestable(KeyPairGenerator kpg, ECGenParameterSpec spec) {
        this.kpg = kpg;
        this.spec = spec;
    }

    public int getKeysize() {
        return keysize;
    }

    public AlgorithmParameterSpec getSpec() {
        return spec;
    }

    public KeyPairGenerator getKpg() {
        return kpg;
    }

    public KeyPair getKeyPair() {
        return kp;
    }

    @Override
    public void run() {
        try {
            stage = KeyGeneratorStage.Init;
            try {
                if (spec != null) {
                    kpg.initialize(spec);
                } else if (keysize != 0) {
                    kpg.initialize(keysize);
                }
            } catch (InvalidAlgorithmParameterException e) {
                failOnException(e);
                return;
            }

            stage = KeyGeneratorStage.GenKeyPair;
            kp = kpg.genKeyPair();

            ok = true;
        } catch (Exception ex) {
            ok = false;
            error = true;
            errorCause = ex;
        }
        hasRun = true;
    }

    public enum KeyGeneratorStage {
        Init,
        GenKeyPair
    }
}
