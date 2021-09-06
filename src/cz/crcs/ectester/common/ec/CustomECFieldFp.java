package cz.crcs.ectester.common.ec;

import java.math.BigInteger;
import java.security.spec.ECFieldFp;

/**
 * @author David Hofman
 */
public class CustomECFieldFp extends ECFieldFp {
    private BigInteger p;

    public CustomECFieldFp(BigInteger p) {
        //feed the constructor of the superclass some default, valid parameter p
        //getters will return custom (and possibly invalid) data
        super(BigInteger.ONE);
        this.p = p;
    }


    @Override
    public int getFieldSize() {
        return p.bitCount();
    }

    @Override
    public BigInteger getP() {
        return p;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else {
            return o instanceof CustomECFieldFp && p.equals(((CustomECFieldFp) o).p);
        }
    }

    @Override
    public int hashCode() {
        return p.hashCode();
    }
}
