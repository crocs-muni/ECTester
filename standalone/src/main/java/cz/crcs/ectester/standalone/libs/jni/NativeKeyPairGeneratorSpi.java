package cz.crcs.ectester.standalone.libs.jni;

import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.data.EC_Store;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.AlgorithmParameters;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class NativeKeyPairGeneratorSpi extends KeyPairGeneratorSpi {
    private int keysize;
    private SecureRandom random;
    private AlgorithmParameterSpec params;
    private boolean useKeysize;
    private boolean useParams;

    public static final int DEFAULT_KEYSIZE = 256;

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
            throw new InvalidAlgorithmParameterException("Not supported.");
        }
        this.params = params;
        this.random = random;
        this.useParams = true;
        this.useKeysize = false;
    }

    @Override
    public KeyPair generateKeyPair() {
        if (!useKeysize && !useParams) {
            if (keysizeSupported(DEFAULT_KEYSIZE)) {
                initialize(DEFAULT_KEYSIZE, new SecureRandom());
            }
        }

        if (useKeysize) {
            return generate(keysize, random);
        } else if (useParams) {
            return generate(params, random);
        } else {
            throw new IllegalStateException("Uninitialized KeyPair.");
        }
    }

    abstract boolean keysizeSupported(int keysize);

    abstract boolean paramsSupported(AlgorithmParameterSpec params);

    abstract KeyPair generate(int keysize, SecureRandom random);

    abstract KeyPair generate(AlgorithmParameterSpec params, SecureRandom random);


    public static class TomCrypt extends NativeKeyPairGeneratorSpi {

        public TomCrypt() {
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

    public static abstract class Botan extends NativeKeyPairGeneratorSpi {
        private String type;

        public Botan(String type) {
            this.type = type;
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

    public static class BotanECDH extends Botan {

        public BotanECDH() {
            super("ECDH");
        }
    }

    public static class BotanECDSA extends Botan {

        public BotanECDSA() {
            super("ECDSA");
        }
    }

    public static class BotanECKCDSA extends Botan {

        public BotanECKCDSA() {
            super("ECKCDSA");
        }
    }

    public static class BotanECGDSA extends Botan {

        public BotanECGDSA() {
            super("ECGDSA");
        }
    }

    public static abstract class Cryptopp extends NativeKeyPairGeneratorSpi {
        private String type;

        public Cryptopp(String type) {
            this.type = type;
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

    public static class CryptoppECDH extends Cryptopp {

        public CryptoppECDH() {
            super("ECDH");
        }
    }

    public static class CryptoppECDSA extends Cryptopp {

        public CryptoppECDSA() {
            super("ECDSA");
        }
    }

    public static class Openssl extends NativeKeyPairGeneratorSpi {
        public Openssl() {
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

    public static class Boringssl extends NativeKeyPairGeneratorSpi {
        public Boringssl() {
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

    public static class Gcrypt extends NativeKeyPairGeneratorSpi {

        public Gcrypt() {
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

    public static abstract class Mscng extends NativeKeyPairGeneratorSpi {
        private String type;

        public Mscng(String type) {
            this.type = type;
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

    public static class MscngECDH extends Mscng {

        public MscngECDH() {
            super("ECDH");
        }
    }

    public static class MscngECDSA extends Mscng {

        public MscngECDSA() {
            super("ECDSA");
        }
    }

    public static class MbedTLS extends NativeKeyPairGeneratorSpi {

        public MbedTLS() {
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

    public static class Ippcp extends NativeKeyPairGeneratorSpi {

        public Ippcp() {
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

    public static class Matrixssl extends NativeKeyPairGeneratorSpi {

        public Matrixssl() {
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
  
    public static class Libressl extends NativeKeyPairGeneratorSpi {

        public Libressl() {
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

    public static class Nettle extends NativeKeyPairGeneratorSpi {
        public Nettle() {
            initialize(256, new SecureRandom());
        }

        @Override
        native boolean keysizeSupported(int keysize);

        @Override
        native boolean paramsSupported(AlgorithmParameterSpec params);

        @Override
        native KeyPair generate(int keysize, SecureRandom random);

        @Override
        KeyPair generate(AlgorithmParameterSpec params, SecureRandom random) {
            if (params instanceof ECGenParameterSpec) {
                    String curveName = ((ECGenParameterSpec) params).getName();
                    if (curveName.contains("secp")) {
                        curveName = "secg/" + curveName;
                    }
                    EC_Curve curve = EC_Store.getInstance().getObject(EC_Curve.class, curveName);
                    ECParameterSpec spec = curve.toSpec();
                    return generate(params, random, spec);
            }
            return null;
        }

        native KeyPair generate(AlgorithmParameterSpec params, SecureRandom random, AlgorithmParameterSpec spec);
    }
}
