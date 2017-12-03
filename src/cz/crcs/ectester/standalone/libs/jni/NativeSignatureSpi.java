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
}
