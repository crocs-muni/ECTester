package cz.crcs.ectester.common.util;

import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.ec.*;
import cz.crcs.ectester.data.EC_Store;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class ECUtil {

    public static byte[] toByteArray(BigInteger what, int bits) {
        byte[] raw = what.toByteArray();
        int bytes = (bits + 7) / 8;
        if (raw.length < bytes) {
            byte[] result = new byte[bytes];
            System.arraycopy(raw, 0, result, bytes - raw.length, raw.length);
            return result;
        }
        if (bytes < raw.length) {
            byte[] result = new byte[bytes];
            System.arraycopy(raw, raw.length - bytes, result, 0, bytes);
            return result;
        }
        return raw;
    }

    public static byte[] toX962Compressed(byte[][] point) {
        if (point.length != 2) {
            return null;
        }
        byte ybit = (byte) (point[1][point[1].length - 1] % 2);
        return ByteUtil.concatenate(new byte[]{(byte) (0x02 | ybit)}, point[0]);
    }

    public static byte[] toX962Compressed(ECPoint point, int bits) {
        if (point.equals(ECPoint.POINT_INFINITY)) {
            return new byte[]{0};
        }
        byte[] x = toByteArray(point.getAffineX(), bits);
        byte marker = (byte) (0x02 | point.getAffineY().mod(BigInteger.valueOf(2)).byteValue());
        return ByteUtil.concatenate(new byte[]{marker}, x);
    }

    public static byte[] toX962Compressed(ECPoint point, ECParameterSpec spec) {
        return toX962Compressed(point, spec.getOrder().bitLength());
    }

    public static byte[] toX962Uncompressed(ECPoint point, int bits) {
        if (point.equals(ECPoint.POINT_INFINITY)) {
            return new byte[]{0};
        }
        byte[] x = toByteArray(point.getAffineX(), bits);
        byte[] y = toByteArray(point.getAffineY(), bits);
        return ByteUtil.concatenate(new byte[]{0x04}, x, y);
    }

    public static byte[] toX962Uncompressed(ECPoint point, ECParameterSpec spec) {
        return toX962Uncompressed(point, spec.getOrder().bitLength());
    }

    public static byte[] toX962Hybrid(ECPoint point, int bits) {
        if (point.equals(ECPoint.POINT_INFINITY)) {
            return new byte[]{0};
        }
        byte[] x = toByteArray(point.getAffineX(), bits);
        byte[] y = toByteArray(point.getAffineY(), bits);
        byte marker = (byte) (0x06 | point.getAffineY().mod(BigInteger.valueOf(2)).byteValue());
        return ByteUtil.concatenate(new byte[]{marker}, x, y);
    }

    public static byte[] toX962Hybrid(ECPoint point, EllipticCurve curve) {
        return toX962Hybrid(point, curve.getField().getFieldSize());
    }

    public static byte[] toX962Hybrid(ECPoint point, ECParameterSpec spec) {
        return toX962Hybrid(point, spec.getCurve());
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
            return new ECPoint(new BigInteger(1, xbytes), new BigInteger(1, ybytes));
        } else if (data[0] == 0x02 || data[0] == 0x03) {
            if (curve == null) {
                throw new IllegalArgumentException();
            }
            byte[] xbytes = new byte[data.length - 1];
            System.arraycopy(data, 1, xbytes, 0, data.length - 1);
            BigInteger x = new BigInteger(1, xbytes);
            BigInteger a = curve.getA();
            BigInteger b = curve.getB();

            ECField field = curve.getField();
            if (field instanceof ECFieldFp) {
                BigInteger p = ((ECFieldFp) field).getP();
                BigInteger alpha = x.modPow(BigInteger.valueOf(3), p);
                alpha = alpha.add(x.multiply(a));
                alpha = alpha.add(b);

                if (!isResidue(alpha, p)) {
                    throw new IllegalArgumentException();
                }

                BigInteger beta = modSqrt(alpha, p);
                if (beta.getLowestSetBit() == 0) {
                    // rightmost bit is one
                    if (data[0] == 0x02) {
                        // yp is 0
                        beta = p.subtract(beta);
                    }
                } else {
                    // rightmost bit is zero
                    if (data[0] == 0x03) {
                        // yp is 1
                        beta = p.subtract(beta);
                    }
                }

                return new ECPoint(x, beta);
            } else if (field instanceof ECFieldF2m) {
                //TODO
                throw new UnsupportedOperationException();
            }
            return null;
        } else {
            throw new IllegalArgumentException();
        }
    }

    private static ECPoint toPoint(EC_Params params) {
        return new ECPoint(
                new BigInteger(1, params.getParam(EC_Consts.PARAMETER_W)[0]),
                new BigInteger(1, params.getParam(EC_Consts.PARAMETER_W)[1]));
    }

    private static BigInteger toScalar(EC_Params params) {
        return new BigInteger(1, params.getParam(EC_Consts.PARAMETER_S)[0]);
    }

    public static ECPublicKey toPublicKey(EC_Key.Public pubkey) {
        EC_Curve curve = EC_Store.getInstance().getObject(EC_Curve.class, pubkey.getCurve());
        if (curve == null) {
            throw new IllegalArgumentException("pubkey curve nor found: " + pubkey.getCurve());
        }
        return new RawECPublicKey(toPoint(pubkey), curve.toSpec());
    }

    public static ECPrivateKey toPrivateKey(EC_Key.Private privkey) {
        EC_Curve curve = EC_Store.getInstance().getObject(EC_Curve.class, privkey.getCurve());
        if (curve == null) {
            throw new IllegalArgumentException("privkey curve nor found: " + privkey.getCurve());
        }
        return new RawECPrivateKey(toScalar(privkey), curve.toSpec());
    }

    public static KeyPair toKeyPair(EC_Keypair kp) {
        EC_Curve curve = EC_Store.getInstance().getObject(EC_Curve.class, kp.getCurve());
        if (curve == null) {
            throw new IllegalArgumentException("keypair curve nor found: " + kp.getCurve());
        }
        ECPublicKey pubkey = new RawECPublicKey(toPoint(kp), curve.toSpec());
        ECPrivateKey privkey = new RawECPrivateKey(toScalar(kp), curve.toSpec());
        return new KeyPair(pubkey, privkey);
    }

    public static byte[] toDERSignature(byte[] r, byte[] s) {
        return ByteUtil.concatenate(new byte[]{0x30, (byte) (r.length + s.length + 4), 0x02, (byte) r.length}, r, new byte[]{0x02, (byte) s.length}, s);
    }
}
