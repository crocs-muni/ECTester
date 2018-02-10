package cz.crcs.ectester.standalone.test;

import cz.crcs.ectester.common.test.BaseTestable;
import cz.crcs.ectester.common.test.TestException;

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
public class KeyAgreementTestable extends BaseTestable {
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
        if (kgtPrivate != null) {
            privateKey = (ECPrivateKey) kgtPrivate.getKeyPair().getPrivate();
        }

        if (kgtPublic != null) {
            publicKey = (ECPublicKey) kgtPublic.getKeyPair().getPublic();
        }

        try {
            if (spec != null) {
                ka.init(privateKey, spec);
            } else {
                ka.init(privateKey);
            }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            ok = false;
            error = true;
            hasRun = true;
            return;
        }

        try {
            ka.doPhase(publicKey, true);
        } catch (IllegalStateException e) {
            ok = false;
            hasRun = true;
            return;
        } catch (InvalidKeyException e) {
            ok = false;
            error = true;
            hasRun = true;
            return;
        }

        try {
            secret = ka.generateSecret();
        } catch (IllegalStateException isex) {
            ok = false;
            hasRun = true;
            return;
        } catch (UnsupportedOperationException uoe) {
            ok = false;
            error = true;
            hasRun = false;
            return;
        }

        ok = true;
        hasRun = true;
    }
}
