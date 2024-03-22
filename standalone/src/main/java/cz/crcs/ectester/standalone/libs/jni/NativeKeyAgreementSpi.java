package cz.crcs.ectester.standalone.libs.jni;

import cz.crcs.ectester.common.util.ECUtil;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class NativeKeyAgreementSpi extends KeyAgreementSpi {
    ECPrivateKey privateKey;
    ECPublicKey publicKey;
    AlgorithmParameterSpec params;

    @Override
    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException {
        if (!(key instanceof ECPrivateKey)) {
            throw new InvalidKeyException
                    ("Key must be instance of ECPrivateKey");
        }
        privateKey = (ECPrivateKey) key;
        this.params = privateKey.getParams();
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase) throws InvalidKeyException, IllegalStateException {
        if (privateKey == null) {
            throw new IllegalStateException("Not initialized");
        }
        if (publicKey != null) {
            throw new IllegalStateException("Phase already executed");
        }
        if (!lastPhase) {
            throw new IllegalStateException
                    ("Only two party agreement supported, lastPhase must be true");
        }
        if (!(key instanceof ECPublicKey)) {
            throw new InvalidKeyException
                    ("Key must be an instance of ECPublicKey");
        }
        publicKey = (ECPublicKey) key;
        return null;
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset) throws IllegalStateException, ShortBufferException {
        byte[] secret = engineGenerateSecret();
        if (sharedSecret.length < offset + secret.length) {
            throw new ShortBufferException();
        }
        System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
        return secret.length;
    }

    private abstract static class SimpleKeyAgreementSpi extends NativeKeyAgreementSpi {

        @Override
        protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
            if (!(params instanceof ECParameterSpec)) {
                throw new InvalidAlgorithmParameterException(params.toString());
            }
            engineInit(key, random);
            this.params = params;
        }

        private byte[] getPubkey() {
            if (publicKey instanceof NativeECPublicKey) {
                return ((NativeECPublicKey) publicKey).getData();
            } else {
                return ECUtil.toX962Uncompressed(publicKey.getW(), ((ECParameterSpec) params));
            }
        }

        private byte[] getPrivkey() {
            if (privateKey instanceof NativeECPrivateKey) {
                return ((NativeECPrivateKey) privateKey).getData();
            } else {
                return ECUtil.toByteArray(privateKey.getS(), ((ECParameterSpec) params).getOrder().bitLength());
            }
        }

        @Override
        protected byte[] engineGenerateSecret() throws IllegalStateException {
            return generateSecret(getPubkey(), getPrivkey(), (ECParameterSpec) params);
        }

        abstract byte[] generateSecret(byte[] pubkey, byte[] privkey, ECParameterSpec params);

        @Override
        protected SecretKey engineGenerateSecret(String algorithm) throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {
            if (algorithm == null) {
                throw new NoSuchAlgorithmException("Algorithm must not be null");
            }
            return generateSecret(getPubkey(), getPrivkey(), (ECParameterSpec) params, algorithm);
        }

        abstract SecretKey generateSecret(byte[] pubkey, byte[] privkey, ECParameterSpec params, String algorithm);
    }

    private abstract static class ExtendedKeyAgreementSpi extends NativeKeyAgreementSpi {

        @Override
        protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
            if (!(params instanceof ECParameterSpec || params instanceof ECGenParameterSpec)) {
                throw new InvalidAlgorithmParameterException();
            }
            engineInit(key, random);
            this.params = params;
        }

        @Override
        protected byte[] engineGenerateSecret() throws IllegalStateException {
            return generateSecret(publicKey, privateKey, params);
        }

        abstract byte[] generateSecret(ECPublicKey pubkey, ECPrivateKey privkey, AlgorithmParameterSpec params);

        @Override
        protected SecretKey engineGenerateSecret(String algorithm) throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {
            if (algorithm == null) {
                throw new NoSuchAlgorithmException("Algorithm must not be null");
            }
            return generateSecret(publicKey, privateKey, params, algorithm);
        }

        abstract SecretKey generateSecret(ECPublicKey pubkey, ECPrivateKey privkey, AlgorithmParameterSpec params, String algorithm);
    }


    public static class TomCrypt extends SimpleKeyAgreementSpi {

        @Override
        native byte[] generateSecret(byte[] pubkey, byte[] privkey, ECParameterSpec params);

        @Override
        native SecretKey generateSecret(byte[] pubkey, byte[] privkey, ECParameterSpec params, String algorithm);
    }

    public abstract static class Botan extends SimpleKeyAgreementSpi {
        private String type;

        public Botan(String type) {
            this.type = type;
        }

        @Override
        native byte[] generateSecret(byte[] pubkey, byte[] privkey, ECParameterSpec params);

        @Override
        native SecretKey generateSecret(byte[] pubkey, byte[] privkey, ECParameterSpec params, String algorithm);
    }

    public static class BotanECDH extends Botan {
        public BotanECDH() {
            super("ECDH");
        }
    }

    public static class BotanECDHwithSHA1KDF extends Botan {
        public BotanECDHwithSHA1KDF() {
            super("ECDHwithSHA1KDF");
        }
    }

    public static class BotanECDHwithSHA224KDF extends Botan {
        public BotanECDHwithSHA224KDF() {
            super("ECDHwithSHA224KDF");
        }
    }

    public static class BotanECDHwithSHA256KDF extends Botan {
        public BotanECDHwithSHA256KDF() {
            super("ECDHwithSHA256KDF");
        }
    }

    public static class BotanECDHwithSHA384KDF extends Botan {
        public BotanECDHwithSHA384KDF() {
            super("ECDHwithSHA384KDF");
        }
    }

    public static class BotanECDHwithSHA512KDF extends Botan {
        public BotanECDHwithSHA512KDF() {
            super("ECDHwithSHA512KDF");
        }
    }

    public abstract static class Cryptopp extends SimpleKeyAgreementSpi {
        private String type;

        public Cryptopp(String type) {
            this.type = type;
        }

        @Override
        native byte[] generateSecret(byte[] pubkey, byte[] privkey, ECParameterSpec params);

        @Override
        native SecretKey generateSecret(byte[] pubkey, byte[] privkey, ECParameterSpec params, String algorithm);
    }

    public static class CryptoppECDH extends Cryptopp {
        public CryptoppECDH() {
            super("ECDH");
        }
    }

    public abstract static class Openssl extends SimpleKeyAgreementSpi {
        private String type;

        public Openssl(String type) {
            this.type = type;
        }

        @Override
        native byte[] generateSecret(byte[] pubkey, byte[] privkey, ECParameterSpec params);

        @Override
        native SecretKey generateSecret(byte[] pubkey, byte[] privkey, ECParameterSpec params, String algorithm);
    }

    public static class OpensslECDH extends Openssl {
        public OpensslECDH() {
            super("ECDH");
        }
    }

    public abstract static class Boringssl extends SimpleKeyAgreementSpi {
        private String type;

        public Boringssl(String type) {
            this.type = type;
        }

        @Override
        native byte[] generateSecret(byte[] pubkey, byte[] privkey, ECParameterSpec params);

        @Override
        native SecretKey generateSecret(byte[] pubkey, byte[] privkey, ECParameterSpec params, String algorithm);
    }

    public static class BoringsslECDH extends Boringssl {
        public BoringsslECDH() {
            super("ECDH");
        }
    }

    public abstract static class Gcrypt extends SimpleKeyAgreementSpi {
        private String type;

        public Gcrypt(String type) {
            this.type = type;
        }

        @Override
        native byte[] generateSecret(byte[] pubkey, byte[] privkey, ECParameterSpec params);

        @Override
        native SecretKey generateSecret(byte[] pubkey, byte[] privkey, ECParameterSpec params, String algorithm);
    }

    public static class GcryptECDH extends Gcrypt {
        public GcryptECDH() {
            super("ECDH");
        }
    }


    public abstract static class Mscng extends ExtendedKeyAgreementSpi {
        private String type;

        public Mscng(String type) {
            this.type = type;
        }

        @Override
        native byte[] generateSecret(ECPublicKey pubkey, ECPrivateKey privkey, AlgorithmParameterSpec params);

        @Override
        native SecretKey generateSecret(ECPublicKey pubkey, ECPrivateKey privkey, AlgorithmParameterSpec params, String algorithm);
    }

    public static class MscngECDHwithSHA1KDF extends Mscng {
        public MscngECDHwithSHA1KDF() {
            super("ECDHwithSHA1KDF(CNG)");
        }
    }

    public static class MscngECDHwithSHA256KDF extends Mscng {
        public MscngECDHwithSHA256KDF() {
            super("ECDHwithSHA256KDF(CNG)");
        }
    }

    public static class MscngECDHwithSHA384KDF extends Mscng {
        public MscngECDHwithSHA384KDF() {
            super("ECDHwithSHA384KDF(CNG)");
        }
    }

    public static class MscngECDHwithSHA512KDF extends Mscng {
        public MscngECDHwithSHA512KDF() {
            super("ECDHwithSHA512KDF(CNG)");
        }
    }

    public abstract static class MbedTLS extends SimpleKeyAgreementSpi {
        private String type;

        public MbedTLS(String type) {
            this.type = type;
        }

        @Override
        native byte[] generateSecret(byte[] pubkey, byte[] privkey, ECParameterSpec params);

        @Override
        native SecretKey generateSecret(byte[] pubkey, byte[] privkey, ECParameterSpec params, String algorithm);
    }

    public static class MbedTLSECDH extends MbedTLS {
        public MbedTLSECDH() {
            super("ECDH");
        }
    }

    public abstract static class Ippcp extends SimpleKeyAgreementSpi {
        private String type;

        public Ippcp(String type) {
            this.type = type;
        }

        @Override
        native byte[] generateSecret(byte[] pubkey, byte[] privkey, ECParameterSpec params);

        @Override
        native SecretKey generateSecret(byte[] pubkey, byte[] privkey, ECParameterSpec params, String algorithm);
    }

    public static class IppcpECDH extends Ippcp {
        public IppcpECDH() {
            super("ECDH");
        }
    }

    public abstract static class Matrixssl extends SimpleKeyAgreementSpi {
        private String type;

        public Matrixssl(String type) {
            this.type = type;
        }

        @Override
        native byte[] generateSecret(byte[] pubkey, byte[] privkey, ECParameterSpec params);

        @Override
        native SecretKey generateSecret(byte[] pubkey, byte[] privkey, ECParameterSpec params, String algorithm);
    }

    public static class MatrixsslECDH extends Matrixssl {
        public MatrixsslECDH() {
            super("ECDH");
        }
    }

    public abstract static class Libressl extends SimpleKeyAgreementSpi {
        private String type;

        public Libressl(String type) {
              this.type = type;
        }
        
        @Override
        native byte[] generateSecret(byte[] pubkey, byte[] privkey, ECParameterSpec params);

        @Override
        native SecretKey generateSecret(byte[] pubkey, byte[] privkey, ECParameterSpec params, String algorithm);
    }

    public abstract static class Nettle extends SimpleKeyAgreementSpi {
        private String type;

        public Nettle(String type) {
            this.type = type;
        }

        @Override
        byte[] generateSecret(byte[] pubkey, byte[] privkey, ECParameterSpec params) {
            try {
                AlgorithmParameters tmp = AlgorithmParameters.getInstance("EC");
                tmp.init(params);
                ECGenParameterSpec spec = tmp.getParameterSpec(ECGenParameterSpec.class);
                switch (spec.getName()) {
                    case "1.2.840.10045.3.1.7":
                        spec = new ECGenParameterSpec("secp256r1");
                        break;
                    case "1.2.840.10045.3.1.1":
                        spec = new ECGenParameterSpec("secp192r1");
                        break;
                    case "1.3.132.0.33":
                        spec = new ECGenParameterSpec("secp224r1");
                        break;
                    case "1.3.132.0.34":
                        spec = new ECGenParameterSpec("secp384r1");
                        break;
                    case "1.3.132.0.35":
                        spec = new ECGenParameterSpec("secp521r1");
                        break;
                    default:
                        return null;

                }
                return generateSecret(pubkey, privkey, spec);

            } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
                e.printStackTrace();
                return null;
            }
        }

        native byte[] generateSecret(byte[] pubkey, byte[] privkey, ECGenParameterSpec params);

        @Override
        native SecretKey generateSecret(byte[] pubkey, byte[] privkey, ECParameterSpec params, String algorithm);
    }

    public static class NettleECDH extends Nettle {
        public NettleECDH() {
            super("ECDH");
        }
    }
    public static class LibresslECDH extends Libressl {
        public LibresslECDH() {
            super("ECDH");
        }
    }

}
