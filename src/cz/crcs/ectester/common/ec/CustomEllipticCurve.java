package cz.crcs.ectester.common.ec;

import java.math.BigInteger;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.EllipticCurve;

/**
 * @author David Hofman
 */
public class CustomEllipticCurve extends EllipticCurve {
    private ECField field;
    private BigInteger a;
    private BigInteger b;

    public CustomEllipticCurve(ECField field, BigInteger a, BigInteger b) {
        //feed the constructor of the superclass some default, valid EC parameters
        //getters will return custom (and possibly invalid) data instead
        super(new ECFieldFp(BigInteger.ONE), BigInteger.ZERO, BigInteger.ZERO);
        this.field = field;
        this.a = a;
        this.b = b;

    }

    @Override
    public BigInteger getA() {
        return a;
    }

    @Override
    public BigInteger getB() {
        return b;
    }

    @Override
    public ECField getField() {
        return field;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else {
            if (o instanceof CustomEllipticCurve) {
                CustomEllipticCurve otherCurve = (CustomEllipticCurve) o;
                if (field.equals(otherCurve.field) && a.equals(otherCurve.a) && b.equals(otherCurve.b)) {
                    return true;
                }
            }
            return false;
        }
    }

    @Override
    public int hashCode() {
        return field.hashCode() << 6 + (a.hashCode() << 4) + (b.hashCode() << 2);
    }
}
