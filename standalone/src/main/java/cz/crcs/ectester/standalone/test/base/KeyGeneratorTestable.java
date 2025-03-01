package cz.crcs.ectester.standalone.test.base;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class KeyGeneratorTestable extends StandaloneTestable<KeyGeneratorTestable.KeyGeneratorStage> {
    private KeyPairGenerator kpg;
    private int keysize = 0;
    private AlgorithmParameterSpec spec = null;
    private SecureRandom random;

    private KeyPair kp;

    public KeyGeneratorTestable(KeyPairGenerator kpg) {
        this.kpg = kpg;
    }

    KeyGeneratorTestable(Builder builder) {
        this.kpg = builder.kpg;
        this.keysize = builder.keysize;
        this.spec = builder.spec;
        this.random = builder.random;
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

    @Override
    public void reset() {
        super.reset();
        try {
            kpg = KeyPairGenerator.getInstance(kpg.getAlgorithm(), kpg.getProvider());
        } catch (NoSuchAlgorithmException e) {
        }
        kp = null;
    }

    @Override
    public KeyGeneratorTestable clone() {
        try {
            KeyGeneratorTestable kgt = builder()
                    .keyPairGenerator(KeyPairGenerator.getInstance(kpg.getAlgorithm(), kpg.getProvider()))
                    .keysize(keysize)
                    .spec(spec)
                    .random(random)
                    .build();
            kgt.kp = kp;
            return kgt;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
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

        public Builder spec(AlgorithmParameterSpec spec) {
            this.spec = spec;
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
            if (kpg == null) {
                throw new NullPointerException("kpg mus be non-null.");
            }
            if (spec != null && keysize != 0) {
                throw new IllegalStateException("Only one of spec and keysize can be set.");
            }
            return new KeyGeneratorTestable(this);
        }
    }
}
