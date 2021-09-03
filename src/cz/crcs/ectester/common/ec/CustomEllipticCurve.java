package cz.crcs.ectester.common.ec;

import java.math.BigInteger;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.EllipticCurve;

public class CustomEllipticCurve extends EllipticCurve {
    ECField field;
    BigInteger A;
    BigInteger B;

    public CustomEllipticCurve(ECField field, BigInteger A, BigInteger B) {
        //feed the default constructor some default, valid data
        //getters will return custom data instead
        super(new ECFieldFp(BigInteger.ONE), BigInteger.ZERO, BigInteger.ZERO);
        this.field = field;
        this.A = A;
        this.B = B;

    }

    @Override
    public BigInteger getA() {
        return this.A;
    }

    @Override
    public BigInteger getB() {
        return this.B;
    }

    @Override
    public ECField getField() {
        return this.field;
    }
}
