package cz.crcs.ectester.standalone.libs.jni;

import cz.crcs.ectester.common.util.ByteUtil;
import cz.crcs.ectester.common.util.ECUtil;
import org.bouncycastle.util.Arrays;

import javax.swing.event.AncestorEvent;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
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

    private static class ANSIX962 extends NativeECPublicKey {
        byte[] keyData;

        public ANSIX962(byte[] keyData, ECParameterSpec params) {
            super("EC", "ANSI X9.62", params);
            this.keyData = keyData;
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

    public static class TomCrypt extends ANSIX962 {
        public TomCrypt(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }

    public static class Botan extends ANSIX962 {
        public Botan(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }

    public static class Cryptopp extends ANSIX962 {
        public Cryptopp(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }

    public static class Openssl extends ANSIX962 {
        public Openssl(byte[] keyData, ECParameterSpec params) {
            super(keyData, params);
        }
    }

    public static class Mscng extends ANSIX962 {
        private byte[] header;
        private byte[] x;
        private byte[] y;

        public Mscng(byte[] header, byte[] x, byte[] y, ECParameterSpec params) {
            super(ByteUtil.concatenate(new byte[]{0x04}, x, y), params);
            this.header = header;
            this.x = x;
            this.y = y;
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
}