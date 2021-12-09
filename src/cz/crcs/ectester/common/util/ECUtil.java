package cz.crcs.ectester.common.util;

import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.ec.*;
import cz.crcs.ectester.data.EC_Store;
import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.digests.SHA1Digest;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class ECUtil {
    private static Random rand = new Random();

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
        return result.equals(BigInteger.ONE);
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

    private static byte[] hashCurve(EC_Curve curve) {
        int bytes = (curve.getBits() + 7) / 8;
        byte[] result = new byte[bytes];
        SHA1Digest digest = new SHA1Digest();
        byte[] curveName = curve.getId().getBytes(StandardCharsets.US_ASCII);
        digest.update(curveName, 0, curveName.length);
        int written = 0;
        while (written < bytes) {
            byte[] dig = new byte[digest.getDigestSize()];
            digest.doFinal(dig, 0);
            int toWrite = digest.getDigestSize() > bytes - written ? bytes - written : digest.getDigestSize();
            System.arraycopy(dig, 0, result, written, toWrite);
            written += toWrite;
            digest.update(dig, 0, dig.length);
        }
        return result;
    }

    public static EC_Params fullRandomKey(EC_Curve curve) {
        int bytes = (curve.getBits() + 7) / 8;
        byte[] result = new byte[bytes];
        rand.nextBytes(result);
        BigInteger priv = new BigInteger(1, result);
        BigInteger order = new BigInteger(1, curve.getParam(EC_Consts.PARAMETER_R)[0]);
        priv = priv.mod(order);
        return new EC_Params(EC_Consts.PARAMETER_S, new byte[][]{toByteArray(priv, curve.getBits())});
    }

    public static EC_Params fixedRandomKey(EC_Curve curve) {
        byte[] hash = hashCurve(curve);
        BigInteger priv = new BigInteger(1, hash);
        BigInteger order = new BigInteger(1, curve.getParam(EC_Consts.PARAMETER_R)[0]);
        priv = priv.mod(order);
        return new EC_Params(EC_Consts.PARAMETER_S, new byte[][]{toByteArray(priv, curve.getBits())});
    }

    private static BigInteger computeRHS(BigInteger x, BigInteger a, BigInteger b, BigInteger p) {
        BigInteger rhs = x.modPow(BigInteger.valueOf(3), p);
        rhs = rhs.add(a.multiply(x)).mod(p);
        rhs = rhs.add(b).mod(p);
        return rhs;
    }

    public static EC_Params fullRandomPoint(EC_Curve curve) {
        EllipticCurve ecCurve = curve.toCurve();

        BigInteger p;
        if (ecCurve.getField() instanceof ECFieldFp) {
            ECFieldFp fp = (ECFieldFp) ecCurve.getField();
            p = fp.getP();
            if (!p.isProbablePrime(20)) {
                return null;
            }
        } else {
            //TODO
            return null;
        }
        BigInteger x;
        BigInteger rhs;
        do {
            x = new BigInteger(ecCurve.getField().getFieldSize(), rand).mod(p);
            rhs = computeRHS(x, ecCurve.getA(), ecCurve.getB(), p);
        } while (!isResidue(rhs, p));
        BigInteger y = modSqrt(rhs, p);
        if (rand.nextBoolean()) {
            y = p.subtract(y);
        }

        byte[] xArr = toByteArray(x, ecCurve.getField().getFieldSize());
        byte[] yArr = toByteArray(y, ecCurve.getField().getFieldSize());
        return new EC_Params(EC_Consts.PARAMETER_W, new byte[][]{xArr, yArr});
    }

    public static EC_Params fixedRandomPoint(EC_Curve curve) {
        EllipticCurve ecCurve = curve.toCurve();

        BigInteger p;
        if (ecCurve.getField() instanceof ECFieldFp) {
            ECFieldFp fp = (ECFieldFp) ecCurve.getField();
            p = fp.getP();
            if (!p.isProbablePrime(20)) {
                return null;
            }
        } else {
            //TODO
            return null;
        }

        BigInteger x = new BigInteger(1, hashCurve(curve)).mod(p);
        BigInteger rhs = computeRHS(x, ecCurve.getA(), ecCurve.getB(), p);
        while (!isResidue(rhs, p)) {
            x = x.add(BigInteger.ONE).mod(p);
            rhs = computeRHS(x, ecCurve.getA(), ecCurve.getB(), p);
        }
        BigInteger y = modSqrt(rhs, p);
        if (y.bitCount() % 2 == 0) {
            y = p.subtract(y);
        }

        byte[] xArr = toByteArray(x, ecCurve.getField().getFieldSize());
        byte[] yArr = toByteArray(y, ecCurve.getField().getFieldSize());
        return new EC_Params(EC_Consts.PARAMETER_W, new byte[][]{xArr, yArr});
    }

    public static ECPoint toPoint(EC_Params params) {
        return new ECPoint(
                new BigInteger(1, params.getParam(EC_Consts.PARAMETER_W)[0]),
                new BigInteger(1, params.getParam(EC_Consts.PARAMETER_W)[1]));
    }

    public static BigInteger toScalar(EC_Params params) {
        return new BigInteger(1, params.getParam(EC_Consts.PARAMETER_S)[0]);
    }

    public static ECPublicKey toPublicKey(EC_Key.Public pubkey) {
        if (pubkey == null) {
            return null;
        }
        EC_Curve curve = EC_Store.getInstance().getObject(EC_Curve.class, pubkey.getCurve());
        if (curve == null) {
            throw new IllegalArgumentException("pubkey curve not found: " + pubkey.getCurve());
        }
        return new RawECPublicKey(toPoint(pubkey), curve.toSpec());
    }

    public static ECPrivateKey toPrivateKey(EC_Key.Private privkey) {
        if (privkey == null) {
            return null;
        }
        EC_Curve curve = EC_Store.getInstance().getObject(EC_Curve.class, privkey.getCurve());
        if (curve == null) {
            throw new IllegalArgumentException("privkey curve not found: " + privkey.getCurve());
        }
        return new RawECPrivateKey(toScalar(privkey), curve.toSpec());
    }

    public static KeyPair toKeyPair(EC_Keypair kp) {
        if (kp == null) {
            return null;
        }
        EC_Curve curve = EC_Store.getInstance().getObject(EC_Curve.class, kp.getCurve());
        if (curve == null) {
            throw new IllegalArgumentException("keypair curve not found: " + kp.getCurve());
        }
        ECPublicKey pubkey = new RawECPublicKey(toPoint(kp), curve.toSpec());
        ECPrivateKey privkey = new RawECPrivateKey(toScalar(kp), curve.toSpec());
        return new KeyPair(pubkey, privkey);
    }

    public static byte[] toDERSignature(byte[] r, byte[] s) throws IOException {
        ASN1Integer rInt = new ASN1Integer(r);
        ASN1Integer sInt = new ASN1Integer(s);
        DERSequence seq = new DERSequence(new ASN1Encodable[]{rInt, sInt});
        return seq.getEncoded();
    }

    public static BigInteger[] fromDERSignature(byte[] signature) throws IOException {
        ASN1StreamParser parser = new ASN1StreamParser(signature);
        DERSequence sequence = (DERSequence) ((DERSequenceParser) parser.readObject()).getLoadedObject();
        ASN1Integer r = (ASN1Integer) sequence.getObjectAt(0);
        ASN1Integer s = (ASN1Integer) sequence.getObjectAt(1);
        return new BigInteger[]{r.getPositiveValue(), s.getPositiveValue()};
    }

    public static BigInteger recoverSignatureNonce(byte[] signature, byte[] data, BigInteger privkey, ECParameterSpec params, String hashType) {
        try {
            int bitSize = params.getOrder().bitLength();
            // Hash the data.
            byte[] hash;
            if (hashType == null || hashType.equals("NONE")) {
                hash = data;
            } else {
                MessageDigest md = MessageDigest.getInstance(hashType);
                hash = md.digest(data);
            }
            // Trim bitSize of rightmost bits.
            BigInteger hashInt = new BigInteger(1, hash);
            int hashBits = hashInt.bitLength();
            if (hashBits > bitSize) {
                hashInt = hashInt.shiftRight(hashBits - bitSize);
            }

            // Parse DERSignature
            BigInteger[] sigPair = fromDERSignature(signature);
            BigInteger r = sigPair[0];
            BigInteger s = sigPair[1];

            BigInteger rd = privkey.multiply(r).mod(params.getOrder());
            BigInteger hrd = hashInt.add(rd).mod(params.getOrder());
            return s.modInverse(params.getOrder()).multiply(hrd).mod(params.getOrder());
        } catch (NoSuchAlgorithmException | IOException | ArithmeticException ex) {
            ex.printStackTrace();
            return null;
        }
    }

    public static EC_Params joinParams(EC_Params... params) {
        List<EC_Params> paramList = new LinkedList<>();
        short paramMask = 0;
        int len = 0;
        for (EC_Params param : params) {
            if (param == null) {
                continue;
            }
            int i = 0;
            for (; i + 1 < paramList.size(); ++i) {
                if (paramList.get(i + 1).getParams() == param.getParams()) {
                    throw new IllegalArgumentException();
                }
                if (paramList.get(i + 1).getParams() < param.getParams()) {
                    break;
                }
            }
            paramList.add(i, param);
            paramMask |= param.getParams();
            len += param.numParams();
        }

        byte[][] res = new byte[len][];
        int i = 0;
        for (EC_Params param : params) {
            for (byte[] data : param.getData()) {
                res[i++] = data.clone();
            }
        }
        return new EC_Params(paramMask, res);
    }

    public static EC_Params loadParams(short params, String named, String file) throws IOException {
        EC_Params result = null;
        if (file != null) {
            result = new EC_Params(params);

            FileInputStream in = new FileInputStream(file);
            result.readCSV(in);
            in.close();
        } else if (named != null) {
            if (params == EC_Consts.PARAMETER_W) {
                result = EC_Store.getInstance().getObject(EC_Key.Public.class, named);
            } else if (params == EC_Consts.PARAMETER_S) {
                result = EC_Store.getInstance().getObject(EC_Key.Private.class, named);
            }

            if (result == null) {
                result = EC_Store.getInstance().getObject(EC_Keypair.class, named);
            }
        }
        return result;
    }

    public static ECKey loadKey(short params, String named, String file, AlgorithmParameterSpec spec) throws IOException {
        if (params == EC_Consts.PARAMETERS_KEYPAIR) {
            throw new IllegalArgumentException();
        }
        EC_Params param = loadParams(params, named, file);
        if (param != null) {
            if (params == EC_Consts.PARAMETER_W) {
                return new RawECPublicKey(toPoint(param), (ECParameterSpec) spec);
            } else if (params == EC_Consts.PARAMETER_S) {
                return new RawECPrivateKey(toScalar(param), (ECParameterSpec) spec);
            }
        }
        return null;
    }

    public static boolean equalKeyPairParameters(ECPrivateKey priv, ECPublicKey pub) {
        if(priv == null || pub == null) {
            return false;
        }
        return priv.getParams().getCurve().equals(pub.getParams().getCurve()) &&
                priv.getParams().getCofactor() == pub.getParams().getCofactor() &&
                priv.getParams().getGenerator().equals(pub.getParams().getGenerator()) &&
                priv.getParams().getOrder().equals(pub.getParams().getOrder());
    }
}
