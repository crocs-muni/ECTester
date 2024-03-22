package cz.crcs.ectester.common.ec;

import cz.crcs.ectester.common.util.ECUtil;

import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
@SuppressWarnings("serial")
public class RawECPublicKey implements ECPublicKey {
    private ECPoint point;
    private ECParameterSpec params;

    public RawECPublicKey(ECPoint point, ECParameterSpec params) {
        this.point = point;
        this.params = params;
    }

    @Override
    public ECPoint getW() {
        return point;
    }

    @Override
    public String getAlgorithm() {
        return "EC";
    }

    @Override
    public String getFormat() {
        return "Raw";
    }

    @Override
    public byte[] getEncoded() {
        return ECUtil.toX962Uncompressed(point, params);
    }

    @Override
    public ECParameterSpec getParams() {
        return params;
    }
}
