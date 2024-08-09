package cz.crcs.ectester.standalone.test.base;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class KeyAgreementTestable extends StandaloneTestable<KeyAgreementTestable.KeyAgreementStage> {
    private KeyAgreement ka;
    private ECPrivateKey privateKey;
    private ECPublicKey publicKey;
    private final KeyGeneratorTestable kgtPrivate;
    private final KeyGeneratorTestable kgtPublic;
    private final AlgorithmParameterSpec spec;
    private final String keyAlgo;
    private final SecureRandom random;

    private byte[] secret;
    private SecretKey derived;

    KeyAgreementTestable(Builder builder) {
        this.ka = builder.ka;
        this.privateKey = builder.privateKey;
        this.publicKey = builder.publicKey;
        this.kgtPrivate = builder.kgtPrivate;
        this.kgtPublic = builder.kgtPublic;
        this.spec = builder.spec;
        this.keyAlgo = builder.keyAlgo;
        this.random = builder.random;
    }

    public String getKeyAlgorithm() {
        return keyAlgo;
    }

    public KeyAgreement getKa() {
        return ka;
    }

    public ECPublicKey getPublicKey() {
        return publicKey;
    }

    public ECPrivateKey getPrivateKey() {
        return privateKey;
    }

    public byte[] getSecret() {
        if (!hasRun) {
            return null;
        }
        return secret;
    }

    public SecretKey getDerivedKey() {
        if (!hasRun) {
            return null;
        }
        return derived;
    }

    @Override
    public void run() {
        try {
            stage = KeyAgreementStage.GetPrivate;
            if (kgtPrivate != null) {
                privateKey = (ECPrivateKey) kgtPrivate.getKeyPair().getPrivate();
            }

            stage = KeyAgreementStage.GetPublic;
            if (kgtPublic != null) {
                publicKey = (ECPublicKey) kgtPublic.getKeyPair().getPublic();
            }

            stage = KeyAgreementStage.Init;
            try {
                if (spec != null) {
                    if (random != null) {
                        ka.init(privateKey, spec, random);
                    } else {
                        ka.init(privateKey, spec);
                    }
                } else {
                    if (random != null) {
                        ka.init(privateKey, random);
                    } else {
                        ka.init(privateKey);
                    }
                }
            } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
                failOnException(e);
                return;
            }

            stage = KeyAgreementStage.DoPhase;
            try {
                ka.doPhase(publicKey, true);
            } catch (IllegalStateException | InvalidKeyException e) {
                failOnException(e);
                return;
            }

            stage = KeyAgreementStage.GenerateSecret;
            try {
                if (keyAlgo != null) {
                    derived = ka.generateSecret(keyAlgo);
                    secret = derived.getEncoded();
                } else {
                    secret = ka.generateSecret();
                }
            } catch (IllegalStateException | UnsupportedOperationException e) {
                failOnException(e);
                return;
            }

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
            ka = KeyAgreement.getInstance(ka.getAlgorithm(), ka.getProvider());
        } catch (NoSuchAlgorithmException e) {
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public enum KeyAgreementStage {
        GetPrivate,
        GetPublic,
        Init,
        DoPhase,
        GenerateSecret
    }

    public static class Builder {
        private KeyAgreement ka;
        private ECPrivateKey privateKey;
        private ECPublicKey publicKey;
        private KeyGeneratorTestable kgtPrivate;
        private KeyGeneratorTestable kgtPublic;
        private AlgorithmParameterSpec spec;
        private String keyAlgo;
        private SecureRandom random;

        public Builder ka(KeyAgreement ka) {
            this.ka = ka;
            return this;
        }

        public Builder privateKey(ECPrivateKey privateKey) {
            this.privateKey = privateKey;
            return this;
        }

        public Builder publicKey(ECPublicKey publicKey) {
            this.publicKey = publicKey;
            return this;
        }

        public Builder privateKgt(KeyGeneratorTestable privateKgt) {
            this.kgtPrivate = privateKgt;
            return this;
        }

        public Builder publicKgt(KeyGeneratorTestable publicKgt) {
            this.kgtPublic = publicKgt;
            return this;
        }

        public Builder spec(AlgorithmParameterSpec spec) {
            this.spec = spec;
            return this;
        }

        public Builder keyAlgo(String keyAlgo) {
            this.keyAlgo = keyAlgo;
            return this;
        }

        public Builder random(SecureRandom random) {
            this.random = random;
            return this;
        }

        public KeyAgreementTestable build() {
            if (ka == null) {
                throw new NullPointerException("ka needs to be non-null.");
            }
            if ((privateKey == null) == (kgtPrivate == null)) {
                throw new IllegalStateException("One of (but not both) privateKey or privateKgt needs to be non-null.");
            }
            if ((publicKey == null) == (kgtPublic == null)) {
                throw new IllegalStateException("One of (but not both) publicKey or publicKgt needs to be non-null.");
            }
            return new KeyAgreementTestable(this);
        }
    }
}
