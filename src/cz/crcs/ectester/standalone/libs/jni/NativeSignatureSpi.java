package cz.crcs.ectester.standalone.libs.jni;

import cz.crcs.ectester.common.util.ECUtil;

import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class NativeSignatureSpi extends SignatureSpi {
    private ECPublicKey verifyKey;
    private ECPrivateKey signKey;
    private ECParameterSpec params;

    private ByteArrayOutputStream buffer = new ByteArrayOutputStream();

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
    protected byte[] engineSign() throws SignatureException {
        return sign(buffer.toByteArray(), ECUtil.toByteArray(signKey.getS(), params.getCurve().getField().getFieldSize()), params);
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        return verify(sigBytes, buffer.toByteArray(), ECUtil.toX962Uncompressed(verifyKey.getW(), params), params);
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

    abstract byte[] sign(byte[] data, byte[] privkey, ECParameterSpec params);

    abstract boolean verify(byte[] signature, byte[] data, byte[] pubkey, ECParameterSpec params);

    public static class TomCryptRaw extends NativeSignatureSpi {

        @Override
        native byte[] sign(byte[] data, byte[] privkey, ECParameterSpec params);

        @Override
        native boolean verify(byte[] signature, byte[] data, byte[] pubkey, ECParameterSpec params);
    }

    public abstract static class Botan extends NativeSignatureSpi {
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

    public abstract static class Cryptopp extends NativeSignatureSpi {
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
}
