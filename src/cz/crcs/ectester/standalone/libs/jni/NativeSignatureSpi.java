package cz.crcs.ectester.standalone.libs.jni;

import cz.crcs.ectester.common.util.ECUtil;

import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class NativeSignatureSpi extends SignatureSpi {
    ECPublicKey verifyKey;
    ECPrivateKey signKey;
    ECParameterSpec params;

    ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof ECPublicKey)) {
            throw new InvalidKeyException
                    ("Key must be an instance of ECPublicKey");
        }
        verifyKey = (ECPublicKey) publicKey;
        params = verifyKey.getParams();
        buffer.reset();
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof ECPrivateKey)) {
            throw new InvalidKeyException
                    ("Key must be an instance of ECPrivateKey");
        }
        signKey = (ECPrivateKey) privateKey;
        params = signKey.getParams();
        buffer.reset();
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        buffer.write(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        buffer.write(b, off, len);
    }


    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new UnsupportedOperationException("setParameter() not supported");
    }

    @Override
    @Deprecated
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new UnsupportedOperationException("getParameter() not supported");
    }

    private abstract static class SimpleSignatureSpi extends NativeSignatureSpi {

        @Override
        protected byte[] engineSign() throws SignatureException {
            byte[] privkey;
            if (signKey instanceof NativeECPrivateKey) {
                privkey = ((NativeECPrivateKey) signKey).getData();
            } else {
                privkey = ECUtil.toByteArray(signKey.getS(), params.getOrder().bitLength());
            }
            return sign(buffer.toByteArray(), privkey, params);
        }

        @Override
        protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
            byte[] pubkey;
            if (verifyKey instanceof NativeECPublicKey) {
                pubkey = ((NativeECPublicKey) verifyKey).getData();
            } else {
                pubkey = ECUtil.toX962Uncompressed(verifyKey.getW(), params);
            }
            return verify(sigBytes, buffer.toByteArray(), pubkey, params);
        }

        abstract byte[] sign(byte[] data, byte[] privkey, ECParameterSpec params);

        abstract boolean verify(byte[] signature, byte[] data, byte[] pubkey, ECParameterSpec params);
    }

    private abstract static class ExtendedSignatureSpi extends NativeSignatureSpi {

        @Override
        protected byte[] engineSign() throws SignatureException {
            return sign(buffer.toByteArray(), signKey, params);
        }

        @Override
        protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
            return verify(sigBytes, buffer.toByteArray(), verifyKey, params);
        }

        abstract byte[] sign(byte[] data, ECPrivateKey privkey, ECParameterSpec params);

        abstract boolean verify(byte[] signature, byte[] data, ECPublicKey pubkey, ECParameterSpec params);
    }

    public static class TomCryptRaw extends SimpleSignatureSpi {

        @Override
        native byte[] sign(byte[] data, byte[] privkey, ECParameterSpec params);

        @Override
        native boolean verify(byte[] signature, byte[] data, byte[] pubkey, ECParameterSpec params);
    }

    public abstract static class Botan extends SimpleSignatureSpi {
        private String type;

        public Botan(String type) {
            this.type = type;
        }

        @Override
        native byte[] sign(byte[] data, byte[] privkey, ECParameterSpec params);

        @Override
        native boolean verify(byte[] signature, byte[] data, byte[] pubkey, ECParameterSpec params);
    }

    public static class BotanECDSAwithNONE extends Botan {

        public BotanECDSAwithNONE() {
            super("NONEwithECDSA");
        }
    }

    public static class BotanECDSAwithSHA1 extends Botan {

        public BotanECDSAwithSHA1() {
            super("SHA1withECDSA");
        }
    }

    public static class BotanECDSAwithSHA224 extends Botan {

        public BotanECDSAwithSHA224() {
            super("SHA224withECDSA");
        }
    }

    public static class BotanECDSAwithSHA256 extends Botan {

        public BotanECDSAwithSHA256() {
            super("SHA256withECDSA");
        }
    }

    public static class BotanECDSAwithSHA384 extends Botan {

        public BotanECDSAwithSHA384() {
            super("SHA384withECDSA");
        }
    }

    public static class BotanECDSAwithSHA512 extends Botan {

        public BotanECDSAwithSHA512() {
            super("SHA512withECDSA");
        }
    }

    public static class BotanECKCDSAwithNONE extends Botan {

        public BotanECKCDSAwithNONE() {
            super("NONEwithECKCDSA");
        }
    }

    public static class BotanECKCDSAwithSHA1 extends Botan {

        public BotanECKCDSAwithSHA1() {
            super("SHA1withECKCDSA");
        }
    }

    public static class BotanECKCDSAwithSHA224 extends Botan {

        public BotanECKCDSAwithSHA224() {
            super("SHA224withECKCDSA");
        }
    }

    public static class BotanECKCDSAwithSHA256 extends Botan {

        public BotanECKCDSAwithSHA256() {
            super("SHA256withECKCDSA");
        }
    }

    public static class BotanECKCDSAwithSHA384 extends Botan {

        public BotanECKCDSAwithSHA384() {
            super("SHA384withECKCDSA");
        }
    }

    public static class BotanECKCDSAwithSHA512 extends Botan {

        public BotanECKCDSAwithSHA512() {
            super("SHA512withECKCDSA");
        }
    }

    public static class BotanECGDSAwithNONE extends Botan {

        public BotanECGDSAwithNONE() {
            super("NONEwithECGDSA");
        }
    }

    public static class BotanECGDSAwithSHA1 extends Botan {

        public BotanECGDSAwithSHA1() {
            super("SHA1withECGDSA");
        }
    }

    public static class BotanECGDSAwithSHA224 extends Botan {

        public BotanECGDSAwithSHA224() {
            super("SHA224withECGDSA");
        }
    }

    public static class BotanECGDSAwithSHA256 extends Botan {

        public BotanECGDSAwithSHA256() {
            super("SHA256withECGDSA");
        }
    }

    public static class BotanECGDSAwithSHA384 extends Botan {

        public BotanECGDSAwithSHA384() {
            super("SHA384withECGDSA");
        }
    }

    public static class BotanECGDSAwithSHA512 extends Botan {

        public BotanECGDSAwithSHA512() {
            super("SHA512withECGDSA");
        }
    }

    public abstract static class Cryptopp extends SimpleSignatureSpi {
        private String type;

        public Cryptopp(String type) {
            this.type = type;
        }

        @Override
        native byte[] sign(byte[] data, byte[] privkey, ECParameterSpec params);

        @Override
        native boolean verify(byte[] signature, byte[] data, byte[] pubkey, ECParameterSpec params);
    }

    public static class CryptoppECDSAwithSHA1 extends Cryptopp {

        public CryptoppECDSAwithSHA1() {
            super("SHA1withECDSA");
        }
    }

    public static class CryptoppECDSAwithSHA224 extends Cryptopp {

        public CryptoppECDSAwithSHA224() {
            super("SHA224withECDSA");
        }
    }

    public static class CryptoppECDSAwithSHA256 extends Cryptopp {

        public CryptoppECDSAwithSHA256() {
            super("SHA256withECDSA");
        }
    }

    public static class CryptoppECDSAwithSHA384 extends Cryptopp {

        public CryptoppECDSAwithSHA384() {
            super("SHA384withECDSA");
        }
    }

    public static class CryptoppECDSAwithSHA512 extends Cryptopp {

        public CryptoppECDSAwithSHA512() {
            super("SHA512withECDSA");
        }
    }

    public abstract static class Openssl extends SimpleSignatureSpi {
        private String type;

        public Openssl(String type) {
            this.type = type;
        }

        @Override
        native byte[] sign(byte[] data, byte[] privkey, ECParameterSpec params);

        @Override
        native boolean verify(byte[] signature, byte[] data, byte[] pubkey, ECParameterSpec params);
    }

    public static class OpensslECDSAwithNONE extends Openssl {

        public OpensslECDSAwithNONE() {
            super("NONEwithECDSA");
        }
    }

    public abstract static class Boringssl extends SimpleSignatureSpi {
        private String type;

        public Boringssl(String type) {
            this.type = type;
        }

        @Override
        native byte[] sign(byte[] data, byte[] privkey, ECParameterSpec params);

        @Override
        native boolean verify(byte[] signature, byte[] data, byte[] pubkey, ECParameterSpec params);
    }

    public static class BoringsslECDSAwithNONE extends Boringssl {

        public BoringsslECDSAwithNONE() {
            super("NONEwithECDSA");
        }
    }

    public abstract static class Gcrypt extends SimpleSignatureSpi {
        private String type;

        public Gcrypt(String type) {
            this.type = type;
        }

        @Override
        native byte[] sign(byte[] data, byte[] privkey, ECParameterSpec params);

        @Override
        native boolean verify(byte[] signature, byte[] data, byte[] pubkey, ECParameterSpec params);
    }

    public static class GcryptECDSAwithNONE extends Gcrypt {

        public GcryptECDSAwithNONE() {
            super("NONEwithECDSA");
        }
    }

    public static class GcryptECDSAwithSHA1 extends Gcrypt {

        public GcryptECDSAwithSHA1() {
            super("SHA1withECDSA");
        }
    }

    public static class GcryptECDSAwithSHA224 extends Gcrypt {

        public GcryptECDSAwithSHA224() {
            super("SHA224withECDSA");
        }
    }

    public static class GcryptECDSAwithSHA256 extends Gcrypt {

        public GcryptECDSAwithSHA256() {
            super("SHA256withECDSA");
        }
    }

    public static class GcryptECDSAwithSHA384 extends Gcrypt {

        public GcryptECDSAwithSHA384() {
            super("SHA384withECDSA");
        }
    }

    public static class GcryptECDSAwithSHA512 extends Gcrypt {

        public GcryptECDSAwithSHA512() {
            super("SHA512withECDSA");
        }
    }

    public static class GcryptECDDSAwithSHA1 extends Gcrypt {

        public GcryptECDDSAwithSHA1() {
            super("SHA1withECDDSA");
        }
    }

    public static class GcryptECDDSAwithSHA224 extends Gcrypt {

        public GcryptECDDSAwithSHA224() {
            super("SHA224withECDDSA");
        }
    }

    public static class GcryptECDDSAwithSHA256 extends Gcrypt {

        public GcryptECDDSAwithSHA256() {
            super("SHA256withECDDSA");
        }
    }

    public static class GcryptECDDSAwithSHA384 extends Gcrypt {

        public GcryptECDDSAwithSHA384() {
            super("SHA384withECDDSA");
        }
    }

    public static class GcryptECDDSAwithSHA512 extends Gcrypt {

        public GcryptECDDSAwithSHA512() {
            super("SHA512withECDDSA");
        }
    }

    public abstract static class MbedTLS extends SimpleSignatureSpi {
        private String type;

        public MbedTLS(String type) {
            this.type = type;
        }

        @Override
        native byte[] sign(byte[] data, byte[] privkey, ECParameterSpec params);

        @Override
        native boolean verify(byte[] signature, byte[] data, byte[] pubkey, ECParameterSpec params);
    }

    public static class MbedTLSECDSAwithNONE extends MbedTLS {

        public MbedTLSECDSAwithNONE() {
            super("NONEwithECDSA");
        }
    }

    public abstract static class Ippcp extends SimpleSignatureSpi {
        private String type;

        public Ippcp(String type) {
            this.type = type;
        }

        @Override
        native byte[] sign(byte[] data, byte[] privkey, ECParameterSpec params);

        @Override
        native boolean verify(byte[] signature, byte[] data, byte[] pubkey, ECParameterSpec params);
    }

    public static class IppcpECDSAwithNONE extends Ippcp {

        public IppcpECDSAwithNONE() {
            super("NONEwithECDSA");
        }
    }

    public abstract static class Libressl extends SimpleSignatureSpi {
        private String type;

        public Libressl(String type) {
            this.type = type;
        }

        @Override
        native byte[] sign(byte[] data, byte[] privkey, ECParameterSpec params);

        @Override
        native boolean verify(byte[] signature, byte[] data, byte[] pubkey, ECParameterSpec params);
    }

    public static class LibresslECDSAwithNONE extends Libressl {

        public LibresslECDSAwithNONE() {
            super("NONEwithECDSA");
        }
    }

    public abstract static class Matrixssl extends SimpleSignatureSpi {
        private String type;

        public Matrixssl(String type) {
            this.type = type;
        }

        @Override
        native byte[] sign(byte[] data, byte[] privkey, ECParameterSpec params);

        @Override
        native boolean verify(byte[] signature, byte[] data, byte[] pubkey, ECParameterSpec params);
    }

    public static class MatrixsslECDSAwithNONE extends Matrixssl {

        public MatrixsslECDSAwithNONE() {
            super("NONEwithECDSA");
        }
    }

    public abstract static class Mscng extends ExtendedSignatureSpi {
        private String type;

        public Mscng(String type) {
            this.type = type;
        }

        @Override
        native byte[] sign(byte[] data, ECPrivateKey privkey, ECParameterSpec params);

        @Override
        native boolean verify(byte[] signature, byte[] data, ECPublicKey pubkey, ECParameterSpec params);
    }

    public static class MscngECDSAwithSHA1 extends Mscng {

        public MscngECDSAwithSHA1() {
            super("SHA1withECDSA");
        }
    }

    public static class MscngECDSAwithSHA256 extends Mscng {

        public MscngECDSAwithSHA256() {
            super("SHA256withECDSA");
        }
    }

    public static class MscngECDSAwithSHA384 extends Mscng {

        public MscngECDSAwithSHA384() {
            super("SHA384withECDSA");
        }
    }

    public static class MscngECDSAwithSHA512 extends Mscng {

        public MscngECDSAwithSHA512() {
            super("SHA512withECDSA");
        }
    }

    public abstract static class Nettle extends SimpleSignatureSpi {
        private String type;

        public Nettle(String type) {
            this.type = type;
        }

        @Override
        byte[] sign(byte[] data, byte[] privKey, ECParameterSpec params) {
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
                return sign(data, privKey, spec);

            } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
                e.printStackTrace();
                return null;
            }
        }

        native byte[] sign(byte[] data, byte[] privKey, ECGenParameterSpec params);

        @Override
        boolean verify(byte[] signature, byte[] data, byte[] pubkey, ECParameterSpec params) {
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
                        return false;
                }
                return verify(signature, data, pubkey, spec);

            } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
                e.printStackTrace();
                return false;
            }
        }

        native boolean verify(byte[] signature, byte[] data, byte[] pubkey, ECGenParameterSpec params);
    }

    public static class NettleECDSAwithNONE extends Nettle {

        public NettleECDSAwithNONE() {
            super("NONEwithECDSA");
        }
    }

}
