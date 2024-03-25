package cz.crcs.ectester.common.ec;

import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

/**
 * @author David Hofman
 */
public class CustomECParameterSpec extends ECParameterSpec {
    private EllipticCurve curve;
    private ECPoint g;
    private BigInteger n;
    private int h;

    public CustomECParameterSpec(EllipticCurve curve, ECPoint g, BigInteger n, int h) {
        //feed the constructor of the superclass some default, valid data
        //getters will return custom (and possibly invalid) parameters instead
        super(new EllipticCurve(new ECFieldFp(BigInteger.ONE),BigInteger.ZERO,BigInteger.ZERO), new ECPoint(BigInteger.ZERO, BigInteger.ZERO), BigInteger.ONE, 1);
        this.curve = curve;
        this.g = g;
        this.n = n;
        this.h = h;
    }

    @Override
    public EllipticCurve getCurve() {
        return curve;
    }

    @Override
    public ECPoint getGenerator() {
        return g;
    }

    @Override
    public BigInteger getOrder() {
        return n;
    }

    @Override
    public int getCofactor() {
        return h;
    }
}
