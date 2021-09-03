package cz.crcs.ectester.common.ec;

import java.math.BigInteger;
import java.security.spec.ECField;

public class CustomECFieldFp implements ECField {
    public BigInteger p;

    public CustomECFieldFp(BigInteger p) {
        this.p = p;
    }

    @Override
    public int getFieldSize() {
        return p.bitCount();
    }

    public BigInteger getP() {
        return p;
    }
}
