package cz.crcs.ectester.standalone.test.base;

import javax.crypto.KeyAgreement;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
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
    private byte[] secret;

    public KeyAgreementTestable(KeyAgreement ka, ECPrivateKey privateKey, ECPublicKey publicKey) {
        this.ka = ka;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public KeyAgreementTestable(KeyAgreement ka, ECPrivateKey privateKey, ECPublicKey publicKey, ECParameterSpec spec) {
        this(ka, privateKey, publicKey);
        this.spec = spec;
    }

    public KeyAgreementTestable(KeyAgreement ka, KeyGeneratorTestable kgt, ECPrivateKey privateKey, ECParameterSpec spec) {
        this(ka, privateKey, null, spec);
        this.kgtPublic = kgt;
    }

    public KeyAgreementTestable(KeyAgreement ka, ECPublicKey publicKey, KeyGeneratorTestable kgt, ECParameterSpec spec) {
        this(ka, null, publicKey, spec);
        this.kgtPrivate = kgt;
    }

    public KeyAgreementTestable(KeyAgreement ka, KeyGeneratorTestable privKgt, KeyGeneratorTestable pubKgt, ECParameterSpec spec) {
        this(ka, (ECPrivateKey) null, null, spec);
        this.kgtPrivate = privKgt;
        this.kgtPublic = pubKgt;
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
                secret = ka.generateSecret();
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

    public enum KeyAgreementStage {
        GetPrivate,
        GetPublic,
        Init,
        DoPhase,
        GenerateSecret
    }
}
