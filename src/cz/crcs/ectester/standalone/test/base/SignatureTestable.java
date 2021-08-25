package cz.crcs.ectester.standalone.test.base;

import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class SignatureTestable extends StandaloneTestable<SignatureTestable.SignatureStage> {
    private Signature sig;
    private ECPrivateKey signKey;
    private ECPublicKey verifyKey;
    private KeyGeneratorTestable kgt;
    private byte[] data;
    private byte[] signature;
    private boolean verified;

    public SignatureTestable(Signature sig, ECPrivateKey signKey, ECPublicKey verifyKey, byte[] data) {
        this.sig = sig;
        this.signKey = signKey;
        this.verifyKey = verifyKey;
        this.data = data;
        if (data == null) {
            SecureRandom random = new SecureRandom();
            this.data = new byte[64];
            random.nextBytes(this.data);
        }
    }

    public SignatureTestable(Signature sig, ECPublicKey verifyKey, byte[] data, byte[] signature) {
        this.sig = sig;
        this.verifyKey = verifyKey;
        this.data = data;
        this.signature = signature;
    }

    public SignatureTestable(Signature sig, KeyGeneratorTestable kgt, byte[] data) {
        this(sig, (ECPrivateKey) null, null, data);
        this.kgt = kgt;
    }

    public Signature getSig() {
        return sig;
    }

    public byte[] getData() {
        return data;
    }

    public byte[] getSignature() {
        return signature;
    }

    public boolean getVerified() {
        return verified;
    }

    @Override
    public void run() {
        try {
            stage = SignatureStage.GetKeys;
            if (kgt != null) {
                signKey = (ECPrivateKey) kgt.getKeyPair().getPrivate();
                verifyKey = (ECPublicKey) kgt.getKeyPair().getPublic();
            }

            if(signKey != null) {
                stage = SignatureStage.InitSign;
                try {
                    sig.initSign(signKey);
                } catch (InvalidKeyException e) {
                    failOnException(e);
                    return;
                }

                stage = SignatureStage.UpdateSign;
                try {
                    sig.update(data);
                } catch (SignatureException e) {
                    failOnException(e);
                    return;
                }

                stage = SignatureStage.Sign;
                try {
                    signature = sig.sign();
                } catch (SignatureException e) {
                    failOnException(e);
                    return;
                }

                ok = true;
            }

            if (verifyKey != null) {
                stage = SignatureStage.InitVerify;
                try {
                    sig.initVerify(verifyKey);
                } catch (InvalidKeyException e) {
                    failOnException(e);
                    return;
                }

                stage = SignatureStage.UpdateVerify;
                try {
                    sig.update(data);
                } catch (SignatureException e) {
                    failOnException(e);
                    return;
                }

                stage = SignatureStage.Verify;
                try {
                    verified = sig.verify(signature);
                } catch (SignatureException e) {
                    failOnException(e);
                    return;
                }

                ok = verified;
            }
        } catch (Exception ex) {
            ok = false;
            error = true;
            errorCause = ex;
        }
        hasRun = true;
    }

    public enum SignatureStage {
        GetKeys,
        InitSign,
        UpdateSign,
        Sign,
        InitVerify,
        UpdateVerify,
        Verify
    }
}
