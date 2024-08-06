package cz.crcs.ectester.standalone.test.base;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
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
    private SecureRandom random;

    public KeyGeneratorTestable(KeyPairGenerator kpg) {
        this.kpg = kpg;
    }

    KeyGeneratorTestable(Builder builder) {
        this.kpg = builder.kpg;
        this.keysize = builder.keysize;
        this.spec = builder.spec;
        this.random = builder.random;
    }
    /*
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
    */

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
                    if (random != null) {
                        kpg.initialize(spec, random);
                    } else {
                        kpg.initialize(spec);
                    }
                } else if (keysize != 0) {
                    if (random != null) {
                        kpg.initialize(keysize, random);
                    } else {
                        kpg.initialize(keysize);
                    }
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

    public static Builder builder() {
        return new Builder();
    }

    public enum KeyGeneratorStage {
        Init,
        GenKeyPair
    }

    public static class Builder {
        private KeyPairGenerator kpg;
        private int keysize = 0;
        private AlgorithmParameterSpec spec = null;
        private SecureRandom random;

        public Builder() {}

        public Builder keyPairGenerator(KeyPairGenerator kpg) {
            this.kpg = kpg;
            return this;
        }

        public Builder keysize(int keysize) {
            this.keysize = keysize;
            return this;
        }

        public Builder spec(ECGenParameterSpec spec) {
            this.spec = spec;
            return this;
        }

        public Builder spec(ECParameterSpec spec) {
            this.spec = spec;
            return this;
        }

        public Builder random(SecureRandom random) {
            this.random = random;
            return this;
        }

        public KeyGeneratorTestable build() {
            return new KeyGeneratorTestable(this);
        }
    }
}
