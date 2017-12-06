package cz.crcs.ectester.standalone.libs.jni;

import org.bouncycastle.util.Arrays;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class NativeECPrivateKey implements ECPrivateKey {
    private String algorithm;
    private String format;

    public NativeECPrivateKey(String algorithm, String format) {
        this.algorithm = algorithm;
        this.format = format;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return format;
    }

    private static class Raw extends NativeECPrivateKey {
        private byte[] keyData;
        private ECParameterSpec params;

        public Raw(byte[] keyData, ECParameterSpec params) {
            super("EC", "raw");
            this.keyData = keyData;
            this.params = params;
        }

        @Override
        public BigInteger getS() {
            return new BigInteger(1, keyData);
        }

        @Override
        public byte[] getEncoded() {
            return Arrays.clone(keyData);
        }

        @Override
        public ECParameterSpec getParams() {
            return params;
        }
    }

    public static class TomCrypt extends Raw {
        public TomCrypt(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }

    public static class Botan extends Raw {
        public Botan(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }
}
