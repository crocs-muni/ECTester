package cz.crcs.ectester.standalone.test.base;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
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
    private KeyGeneratorTestable kgtPrivate;
    private KeyGeneratorTestable kgtPublic;
    private AlgorithmParameterSpec spec;
    private String keyAlgo;
    private byte[] secret;
    private SecretKey derived;

    public KeyAgreementTestable(KeyAgreement ka, ECPrivateKey privateKey, ECPublicKey publicKey) {
        this.ka = ka;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public KeyAgreementTestable(KeyAgreement ka, ECPrivateKey privateKey, ECPublicKey publicKey, String keyAlgo) {
        this(ka, privateKey, publicKey);
        this.keyAlgo = keyAlgo;
    }

    public KeyAgreementTestable(KeyAgreement ka, ECPrivateKey privateKey, ECPublicKey publicKey, ECParameterSpec spec) {
        this(ka, privateKey, publicKey);
        this.spec = spec;
    }

    public KeyAgreementTestable(KeyAgreement ka, ECPrivateKey privateKey, ECPublicKey publicKey, ECParameterSpec spec, String keyAlgo) {
        this(ka, privateKey, publicKey, spec);
        this.keyAlgo = keyAlgo;
    }

    public KeyAgreementTestable(KeyAgreement ka, KeyGeneratorTestable kgt, ECPrivateKey privateKey, ECParameterSpec spec) {
        this(ka, privateKey, null, spec);
        this.kgtPublic = kgt;
    }

    public KeyAgreementTestable(KeyAgreement ka, KeyGeneratorTestable kgt, ECPrivateKey privateKey, ECParameterSpec spec, String keyAlgo) {
        this(ka, kgt, privateKey, spec);
        this.keyAlgo = keyAlgo;
    }

    public KeyAgreementTestable(KeyAgreement ka, ECPublicKey publicKey, KeyGeneratorTestable kgt, ECParameterSpec spec) {
        this(ka, null, publicKey, spec);
        this.kgtPrivate = kgt;
    }

    public KeyAgreementTestable(KeyAgreement ka, ECPublicKey publicKey, KeyGeneratorTestable kgt, ECParameterSpec spec, String keyAlgo) {
        this(ka, publicKey, kgt, spec);
        this.keyAlgo = keyAlgo;
    }

    public KeyAgreementTestable(KeyAgreement ka, KeyGeneratorTestable privKgt, KeyGeneratorTestable pubKgt, ECParameterSpec spec) {
        this(ka, (ECPrivateKey) null, null, spec);
        this.kgtPrivate = privKgt;
        this.kgtPublic = pubKgt;
    }

    public KeyAgreementTestable(KeyAgreement ka, KeyGeneratorTestable privKgt, KeyGeneratorTestable pubKgt, ECParameterSpec spec, String keyAlgo) {
        this(ka, privKgt, pubKgt, spec);
        this.keyAlgo = keyAlgo;
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
                    ka.init(privateKey, spec);
                } else {
                    ka.init(privateKey);
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
        } catch (NoSuchAlgorithmException e) { }
    }

    public enum KeyAgreementStage {
        GetPrivate,
        GetPublic,
        Init,
        DoPhase,
        GenerateSecret
    }
}
