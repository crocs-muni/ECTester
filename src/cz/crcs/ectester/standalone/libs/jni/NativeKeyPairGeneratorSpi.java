package cz.crcs.ectester.standalone.libs.jni;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class NativeKeyPairGeneratorSpi extends KeyPairGeneratorSpi {
    @Override
    public void initialize(int keysize, SecureRandom random) {

    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {

    }

    @Override
    public KeyPair generateKeyPair() {
        return null;
    }

    public static class TomCrypt extends NativeKeyPairGeneratorSpi {
        
    }
}
