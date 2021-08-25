package cz.crcs.ectester.common.ec;

import cz.crcs.ectester.common.util.ECUtil;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
@SuppressWarnings("serial")
public class RawECPrivateKey implements ECPrivateKey {
    private BigInteger scalar;
    private ECParameterSpec params;

    public RawECPrivateKey(BigInteger scalar, ECParameterSpec params) {
        this.scalar = scalar;
        this.params = params;
    }

    @Override
    public BigInteger getS() {
        return scalar;
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
        return ECUtil.toByteArray(scalar, params.getOrder().bitLength());
    }

    @Override
    public ECParameterSpec getParams() {
        return params;
    }
}
