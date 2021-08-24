package cz.crcs.ectester.standalone.libs.jni;

import cz.crcs.ectester.common.util.ByteUtil;
import org.bouncycastle.util.Arrays;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
@SuppressWarnings("serial")
public abstract class NativeECPrivateKey implements ECPrivateKey {
    private String algorithm;
    private String format;
    ECParameterSpec params;

    public NativeECPrivateKey(String algorithm, String format, ECParameterSpec params) {
        this.algorithm = algorithm;
        this.format = format;
        this.params = params;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return format;
    }

    @Override
    public ECParameterSpec getParams() {
        return params;
    }

    public abstract byte[] getData();

    @SuppressWarnings("serial")
    private static class Raw extends NativeECPrivateKey {
        byte[] keyData;

        public Raw(byte[] keyData, ECParameterSpec params) {
            super("EC", "raw", params);
            this.keyData = Arrays.clone(keyData);
        }

        @Override
        public BigInteger getS() {
            return new BigInteger(1, keyData);
        }

        @Override
        public byte[] getEncoded() {
            return Arrays.clone(keyData);
        }

        public byte[] getData() {
            return getEncoded();
        }
    }

    @SuppressWarnings("serial")
    public static class TomCrypt extends Raw {
        public TomCrypt(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }

    @SuppressWarnings("serial")
    public static class Botan extends Raw {
        public Botan(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }

    @SuppressWarnings("serial")
    public static class Cryptopp extends Raw {
        public Cryptopp(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }

    @SuppressWarnings("serial")
    public static class Openssl extends Raw {
        public Openssl(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }

    @SuppressWarnings("serial")
    public static class Boringssl extends Raw {
        public Boringssl(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }

    @SuppressWarnings("serial")
    public static class Gcrypt extends Raw {
        public Gcrypt(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }

    @SuppressWarnings("serial")
    public static class MbedTLS extends Raw {
        public MbedTLS(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }

    @SuppressWarnings("serial")
    public static class Ippcp extends Raw {
        public Ippcp(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }

    @SuppressWarnings("serial")
    public static class Matrixssl extends Raw {
        public Matrixssl(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }

    @SuppressWarnings("serial")
    public static class Libressl extends Raw {
        public Libressl(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }

    @SuppressWarnings("serial")
    public static class Mscng extends Raw {
        // 0 -> implicit (meta = curveName UTF16, header = full);
        // 1 -> explicit (meta = null, header = full);
        // 2 -> nist (meta = null, header = full)
        private int flag;
        private byte[] meta = null;
        private byte[] header;
        private byte[] x;
        private byte[] y;

        public Mscng(int flag, byte[] meta, byte[] header, byte[] x, byte[] y, byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
            this.flag = flag;
            this.meta = Arrays.clone(meta);
            this.header = Arrays.clone(header);
            this.x = Arrays.clone(x);
            this.y = Arrays.clone(y);
        }

        public int getFlag() {
            return flag;
        }

        public byte[] getMeta() {
            return Arrays.clone(meta);
        }

        public byte[] getHeader() {
            return Arrays.clone(header);
        }

        public byte[] getBlob() {
            return ByteUtil.concatenate(header, x, y, keyData);
        }

        @Override
        public byte[] getData() {
            return getBlob();
        }
    }

    @SuppressWarnings("serial")
    public static class Nettle extends Raw {
        public Nettle(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }
}
