package cz.crcs.ectester.common.ec;

import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

public class CustomECParameterSpec extends ECParameterSpec {
    private final EllipticCurve curve;
    private final ECPoint G;
    private final BigInteger R;
    private final int K;

    public CustomECParameterSpec(EllipticCurve curve, ECPoint G, BigInteger R, int K) {
        //feed the constructor of the superclass some default, valid data
        //getters will return custom (and possibly invalid) parameters instead
        super(new EllipticCurve(new ECFieldFp(BigInteger.ONE),BigInteger.ZERO,BigInteger.ZERO), new ECPoint(BigInteger.ZERO, BigInteger.ZERO), BigInteger.ONE, 1);
        this.curve = curve;
        this.G = G;
        this.R = R;
        this.K = K;
    }

    @Override
    public EllipticCurve getCurve() {
        return curve;
    }

    @Override
    public ECPoint getGenerator() {
        return G;
    }

    @Override
    public BigInteger getOrder() {
        return R;
    }

    @Override
    public int getCofactor() {
        return K;
    }
}
