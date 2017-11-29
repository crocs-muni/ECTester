package cz.crcs.ectester.common.util;

import java.math.BigInteger;
import java.security.spec.*;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class ECUtil {
    public static byte[] toX962Compressed(ECPoint point) {
        if (point.equals(ECPoint.POINT_INFINITY)) {
            return new byte[]{0};
        }
        byte[] x = point.getAffineX().toByteArray();
        byte marker = (byte) (0x02 | point.getAffineY().mod(BigInteger.valueOf(2)).byteValue());
        return ByteUtil.concatenate(new byte[]{marker}, x);
    }

    public static byte[] toX962Uncompressed(ECPoint point) {
        if (point.equals(ECPoint.POINT_INFINITY)) {
            return new byte[]{0};
        }
        byte[] x = point.getAffineX().toByteArray();
        byte[] y = point.getAffineY().toByteArray();
        return ByteUtil.concatenate(new byte[]{0x04}, x, y);
    }

    public static byte[] toX962Hybrid(ECPoint point) {
        if (point.equals(ECPoint.POINT_INFINITY)) {
            return new byte[]{0};
        }
        byte[] x = point.getAffineX().toByteArray();
        byte[] y = point.getAffineY().toByteArray();
        byte marker = (byte) (0x06 | point.getAffineY().mod(BigInteger.valueOf(2)).byteValue());
        return ByteUtil.concatenate(new byte[]{marker}, x, y);
    }

    private static boolean isResidue(BigInteger a, BigInteger p) {
        BigInteger exponent = p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));
        BigInteger result = a.modPow(exponent, p);
        return result.intValueExact() == 1;
    }

    private static BigInteger modSqrt(BigInteger a, BigInteger p) {
        BigInteger q = p.subtract(BigInteger.ONE);
        int s = 0;
        while (q.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO)) {
            q = q.divide(BigInteger.valueOf(2));
            s++;
        }

        BigInteger z = BigInteger.ONE;
        do {
            z = z.add(BigInteger.ONE);
        } while (isResidue(z, p));

        BigInteger m = BigInteger.valueOf(s);
        BigInteger c = z.modPow(q, p);
        BigInteger t = a.modPow(q, p);
        BigInteger rExponent = q.add(BigInteger.ONE).divide(BigInteger.valueOf(2));
        BigInteger r = a.modPow(rExponent, p);

        while (!t.equals(BigInteger.ONE)) {
            int i = 0;
            BigInteger exponent;
            do {
               exponent = BigInteger.valueOf(2).pow(++i);
            } while (!t.modPow(exponent, p).equals(BigInteger.ONE));

            BigInteger twoExponent = m.subtract(BigInteger.valueOf(i + 1));
            BigInteger b = c.modPow(BigInteger.valueOf(2).modPow(twoExponent, p), p);
            m = BigInteger.valueOf(i);
            c = b.modPow(BigInteger.valueOf(2), p);
            t = t.multiply(c).mod(p);
            r = r.multiply(b).mod(p);
        }
        return r;
    }

    public static ECPoint fromX962(byte[] data, EllipticCurve curve) {
        if (data == null) {
            return null;
        }
        if (data[0] == 0x04 || data[0] == 0x06 || data[0] == 0x07) {
            int len = (data.length - 1) / 2;
            byte[] xbytes = new byte[len];
            System.arraycopy(data, 1, xbytes, 0, len);
            byte[] ybytes = new byte[len];
            System.arraycopy(data, 1 + len, ybytes, 0, len);
            return new ECPoint(new BigInteger(xbytes), new BigInteger(ybytes));
        } else if (data[0] == 0x02 || data[0] == 0x03) {
            if (curve == null) {
                throw new IllegalArgumentException();
            }
            byte[] xbytes = new byte[data.length - 1];
            System.arraycopy(data, 1, xbytes, 0, data.length - 1);
            BigInteger x = new BigInteger(xbytes);
            BigInteger a = curve.getA();
            BigInteger b = curve.getB();

            ECField field = curve.getField();
            if (field instanceof ECFieldFp) {
                BigInteger p = ((ECFieldFp) field).getP();
                BigInteger alpha = x.modPow(BigInteger.valueOf(3), p);
                alpha = alpha.add(x.multiply(a));
                alpha = alpha.add(b);

                BigInteger beta = modSqrt(alpha, p);
                if (beta.getLowestSetBit() == 0) {
                    // rightmost bit is one
                    if (data[0] == 0x02) {
                        beta = beta.negate();
                    }
                } else {
                    // rightmost bit is zero
                    if (data[0] == 0x03) {
                        beta = beta.negate();
                    }
                }

                return new ECPoint(x, beta);
            } else if (field instanceof ECFieldF2m) {

            }
            return null;
        } else {
            throw new IllegalArgumentException();
        }
    }
}
