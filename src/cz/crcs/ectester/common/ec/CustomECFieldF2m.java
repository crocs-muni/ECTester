package cz.crcs.ectester.common.ec;

import java.math.BigInteger;
import java.security.spec.ECFieldF2m;
import java.util.Arrays;

/**
 * @author David Hofman
 */
public class CustomECFieldF2m extends ECFieldF2m {
    private int m;
    private int[] ks;
    private BigInteger rp;

    public CustomECFieldF2m(int m, int[] ks) {
        //feed the constructor of the superclass some default, valid data
        //getters will return custom parameters instead
        super(163, new int[] {3, 2, 1});
        this.m = m;
        this.ks = ks.clone();

        //causes ArithmeticException if m < 0 or any element of ks < 0
        this.rp = BigInteger.ONE;
        this.rp = this.rp.setBit(m);
        for(int i = 0; i < this.ks.length; ++i) {
            this.rp = this.rp.setBit(this.ks[i]);
        }
    }

    @Override
    public int getFieldSize() {
        return m;
    }

    @Override
    public int getM() {
        return m;
    }

    @Override
    public int[] getMidTermsOfReductionPolynomial() {
        return ks.clone();
    }

    @Override
    public BigInteger getReductionPolynomial() {
        return rp;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (!(o instanceof CustomECFieldF2m)) {
            return false;
        } else {
            return m == ((CustomECFieldF2m) o).m && Arrays.equals(ks, ((CustomECFieldF2m) o).ks);
        }
    }

    @Override
    public int hashCode() {
        int hash = m << 5;
        hash += rp == null ? 0 : rp.hashCode();
        return hash;
    }
}
