package cz.crcs.ectester.standalone.libs.jni;

import cz.crcs.ectester.common.util.ByteUtil;
import cz.crcs.ectester.common.util.ECUtil;
import org.bouncycastle.util.Arrays;

import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
@SuppressWarnings("serial")
public abstract class NativeECPublicKey implements ECPublicKey {
    private String algorithm;
    private String format;
    ECParameterSpec params;

    public NativeECPublicKey(String algorithm, String format, ECParameterSpec params) {
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
    private static class ANSIX962 extends NativeECPublicKey {
        byte[] keyData;

        public ANSIX962(byte[] keyData, ECParameterSpec params) {
            super("EC", "ANSI X9.62", params);
            this.keyData = Arrays.clone(keyData);
        }

        @Override
        public ECPoint getW() {
            return ECUtil.fromX962(keyData, params.getCurve());
        }

        @Override
        public byte[] getEncoded() {
            return Arrays.clone(keyData);
        }

        public byte[] getData() {
            return ECUtil.toX962Uncompressed(getW(), params);
        }
    }

    @SuppressWarnings("serial")
    public static class TomCrypt extends ANSIX962 {
        public TomCrypt(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }

    @SuppressWarnings("serial")
    public static class Botan extends ANSIX962 {
        public Botan(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }

    @SuppressWarnings("serial")
    public static class Cryptopp extends ANSIX962 {
        public Cryptopp(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }

    @SuppressWarnings("serial")
    public static class Openssl extends ANSIX962 {
        public Openssl(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }

    @SuppressWarnings("serial")
    public static class Boringssl extends ANSIX962 {
        public Boringssl(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }

    @SuppressWarnings("serial")
    public static class Gcrypt extends ANSIX962 {
        public Gcrypt(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }

    @SuppressWarnings("serial")
    public static class MbedTLS extends ANSIX962 {
        public MbedTLS(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }

    @SuppressWarnings("serial")
    public static class Ippcp extends ANSIX962 {
        public Ippcp(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }

    @SuppressWarnings("serial")
    public static class Matrixssl extends ANSIX962 {
        public Matrixssl(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }

    @SuppressWarnings("serial")
    public static class Libressl extends ANSIX962 {
        public Libressl(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }

    @SuppressWarnings("serial")
    public static class Mscng extends ANSIX962 {
        // 0 -> implicit (meta = curveName UTF16, header = full);
        // 1 -> explicit (meta = null, header = full);
        // 2 -> nist (meta = null, header = full)
        private int flag;
        private byte[] meta = null;
        private byte[] header;
        private byte[] x;
        private byte[] y;

        public Mscng(int flag, byte[] meta, byte[] header, byte[] x, byte[] y, ECParameterSpec params) {
            super(ByteUtil.concatenate(new byte[]{0x04}, x, y), params);
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
            return ByteUtil.concatenate(header, x, y);
        }

        @Override
        public byte[] getData() {
            return getBlob();
        }
    }

    @SuppressWarnings("serial")
    public static class Nettle extends ANSIX962 {
        public Nettle(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }
}
