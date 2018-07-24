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

    public NativeECPublicKey(String algorithm, String format) {
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

    private static class ANSIX962 extends NativeECPublicKey {
        private byte[] keyData;
        private ECParameterSpec params;

        public ANSIX962(byte[] keyData, ECParameterSpec params) {
            super("EC", "ANSI X9.62");
            this.keyData = keyData;
            this.params = params;
        }

        @Override
        public ECPoint getW() {
            return ECUtil.fromX962(keyData, params.getCurve());
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
        public Mscng(byte[] x, byte[] y, ECParameterSpec params) {
            super(ByteUtil.concatenate(new byte[]{0x04}, x, y), params);
        }
    }
}
