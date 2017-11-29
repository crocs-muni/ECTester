package cz.crcs.ectester.standalone.libs.jni;

import cz.crcs.ectester.common.util.ECUtil;
import org.bouncycastle.util.Arrays;

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

    public static class TomCrypt extends NativeECPublicKey {
        private byte[] keyData;
        private ECParameterSpec params;

        public TomCrypt(byte[] keyData, ECParameterSpec params) {
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
}
