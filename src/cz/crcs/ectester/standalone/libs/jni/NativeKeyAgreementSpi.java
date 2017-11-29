package cz.crcs.ectester.standalone.libs.jni;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class NativeKeyAgreementSpi extends KeyAgreementSpi {
    @Override
    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException {

    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {

    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase) throws InvalidKeyException, IllegalStateException {
        return null;
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException {
        return new byte[0];
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset) throws IllegalStateException, ShortBufferException {
        return 0;
    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm) throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {
        return null;
    }

    public static class TomCrypt extends NativeKeyAgreementSpi {

    }
}
