package cz.crcs.ectester.standalone.libs.jni;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class NativeKeyPairGeneratorSpi extends KeyPairGeneratorSpi {
    private int keysize;
    private SecureRandom random;
    private AlgorithmParameterSpec params;
    private boolean useKeysize;
    private boolean useParams;

    @Override
    public void initialize(int keysize, SecureRandom random) {
        if (!keysizeSupported(keysize)) {
            throw new InvalidParameterException("Keysize " + keysize + " not supported.");
        }
        this.keysize = keysize;
        this.random = random;
        this.useKeysize = true;
        this.useParams = false;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        if (!paramsSupported(params)) {
            throw new InvalidAlgorithmParameterException("not supported.");
        }
        this.params = params;
        this.random = random;
        this.useParams = true;
        this.useKeysize = false;
    }

    @Override
    public KeyPair generateKeyPair() {
        if (useKeysize) {
            return generate(keysize, random);
        } else if (useParams) {
            return generate(params, random);
        }
        return null;
    }

    abstract boolean keysizeSupported(int keysize);

    abstract boolean paramsSupported(AlgorithmParameterSpec params);

    abstract KeyPair generate(int keysize, SecureRandom random);

    abstract KeyPair generate(AlgorithmParameterSpec params, SecureRandom random);

    public static class TomCrypt extends NativeKeyPairGeneratorSpi {

        public TomCrypt() {
            initialize(256, new SecureRandom());
        }

        @Override
        native boolean keysizeSupported(int keysize);

        @Override
        native boolean paramsSupported(AlgorithmParameterSpec params);

        @Override
        native KeyPair generate(int keysize, SecureRandom random);

        @Override
        native KeyPair generate(AlgorithmParameterSpec params, SecureRandom random);
    }

    public static class Botan extends NativeKeyPairGeneratorSpi {

        public Botan() {
            initialize(256, new SecureRandom());
        }

        @Override
        native boolean keysizeSupported(int keysize);

        @Override
        native boolean paramsSupported(AlgorithmParameterSpec params);

        @Override
        native KeyPair generate(int keysize, SecureRandom random);

        @Override
        native KeyPair generate(AlgorithmParameterSpec params, SecureRandom random);
    }
}
