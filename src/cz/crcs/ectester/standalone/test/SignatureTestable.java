package cz.crcs.ectester.standalone.test;

import cz.crcs.ectester.common.test.BaseTestable;
import cz.crcs.ectester.common.test.TestException;

import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class SignatureTestable extends BaseTestable {
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
            this.data = new byte[32];
            random.nextBytes(this.data);
        }
    }

    public SignatureTestable(Signature sig, KeyGeneratorTestable kgt, byte[] data) {
        this(sig, null, null, data);
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
    public void run() throws TestException {
        if (kgt != null) {
            signKey = (ECPrivateKey) kgt.getKeyPair().getPrivate();
            verifyKey = (ECPublicKey) kgt.getKeyPair().getPublic();
        }

        try {
            sig.initSign(signKey);
        } catch (InvalidKeyException e) {
            throw new TestException(e);
        }

        try {
            sig.update(data);
        } catch (SignatureException e) {
            ok = false;
            hasRun = true;
            return;
        }

        try {
            signature = sig.sign();
        } catch (SignatureException e) {
            ok = false;
            hasRun = true;
            return;
        }

        try {
            sig.initVerify(verifyKey);
        } catch (InvalidKeyException e) {
            throw new TestException(e);
        }

        try {
            sig.update(data);
        } catch (SignatureException e) {
            ok = false;
            hasRun = true;
            return;
        }

        try {
            verified = sig.verify(signature);
        } catch (SignatureException e) {
            ok = false;
            hasRun = true;
        }
        ok = true;
        hasRun = true;
    }
}
