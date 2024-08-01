package cz.crcs.ectester.common.util;

import cz.crcs.ectester.common.ec.*;
import cz.crcs.ectester.data.EC_Store;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.signers.PlainDSAEncoding;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.jcajce.interfaces.XDHPrivateKey;
import org.bouncycastle.jcajce.interfaces.XDHPublicKey;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.*;
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
        return toX962Compressed(point, spec.getCurve().getField().getFieldSize());
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
        return toX962Uncompressed(point, spec.getCurve().getField().getFieldSize());
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
            int toWrite = Math.min(digest.getDigestSize(), bytes - written);
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
        if (curve.getField() == EC_Consts.ALG_EC_FP) {
            EllipticCurve ecCurve = curve.toCurve();
            ECFieldFp fp = (ECFieldFp) ecCurve.getField();
            BigInteger p = fp.getP();
            if (!p.isProbablePrime(20)) {
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
        } else {
            ECCurve.F2m bcCurve = (ECCurve.F2m) curve.toBCCurve();
            BigInteger b = new BigInteger(bcCurve.getFieldSize(), rand);
            org.bouncycastle.math.ec.ECPoint point;
            while (true) {
                try {
                    ECFieldElement.F2m x = (ECFieldElement.F2m) bcCurve.fromBigInteger(b);
                    byte[] pointTry = ByteUtil.concatenate(new byte[]{0x02}, x.getEncoded());
                    point = bcCurve.decodePoint(pointTry);
                    break;
                } catch (IllegalArgumentException iae) {
                    b = new BigInteger(bcCurve.getFieldSize(), rand);
                }
            }

            return new EC_Params(EC_Consts.PARAMETER_W, new byte[][] {point.getAffineXCoord().getEncoded(), point.getAffineYCoord().getEncoded()});
        }
    }

    public static EC_Params fixedRandomPoint(EC_Curve curve) {
        if (curve.getField() == EC_Consts.ALG_EC_FP) {
            EllipticCurve ecCurve = curve.toCurve();
            ECFieldFp fp = (ECFieldFp) ecCurve.getField();
            BigInteger p = fp.getP();
            if (!p.isProbablePrime(20)) {
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
        } else {
            ECCurve.F2m bcCurve = (ECCurve.F2m) curve.toBCCurve();
            BigInteger b = new BigInteger(1, hashCurve(curve));
            while (b.bitLength() > bcCurve.getFieldSize()) {
                b = b.shiftRight(1);
            }
            org.bouncycastle.math.ec.ECPoint point;
            while (true) {
                try {
                    ECFieldElement.F2m x = (ECFieldElement.F2m) bcCurve.fromBigInteger(b);
                    byte[] pointTry = ByteUtil.concatenate(new byte[]{0x02}, x.getEncoded());
                    point = bcCurve.decodePoint(pointTry);
                    break;
                } catch (IllegalArgumentException iae) {
                    b = b.add(BigInteger.ONE);
                }
            }
            return new EC_Params(EC_Consts.PARAMETER_W, new byte[][] {point.getAffineXCoord().getEncoded(), point.getAffineYCoord().getEncoded()});
        }
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

    /**
     * Validate DER or PLAIN signature format.
     *
     * @param signature
     * @param params
     * @param hashAlgo
     * @param sigType
     * @throws IllegalArgumentException in case of invalid format.
     */
    public static void validateSignatureFormat(byte[] signature, ECParameterSpec params, String hashAlgo, String sigType) {
        BigInteger n = params.getOrder();
        try {
            if (sigType.contains("CVC") || sigType.contains("PLAIN")) {
                PlainDSAEncoding.INSTANCE.decode(n, signature);
            } else {
                StandardDSAEncoding.INSTANCE.decode(n, signature);
            }
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Recover the ECDSA signature nonce.
     *
     * @param signature
     * @param data
     * @param privkey
     * @param params
     * @param hashAlgo
     * @param sigType
     * @return The nonce.
     */
    public static BigInteger recoverSignatureNonce(byte[] signature, byte[] data, BigInteger privkey, ECParameterSpec params, String hashAlgo, String sigType) {
        // We do not know how to reconstruct those nonces so far.
        // sigType.contains("ECKCDSA") || sigType.contains("ECNR") || sigType.contains("SM2")
        if (!sigType.contains("ECDSA")) {
            return null;
        }
        try {
            BigInteger n = params.getOrder();
            int bitSize = n.bitLength();
            // Hash the data.
            byte[] hash;
            if (hashAlgo == null || hashAlgo.equals("NONE")) {
                hash = data;
            } else {
                MessageDigest md = MessageDigest.getInstance(hashAlgo);
                hash = md.digest(data);
            }
            // Trim bitSize of rightmost bits.
            BigInteger hashInt = new BigInteger(1, hash);
            int hashBits = hashInt.bitLength();
            if (hashBits > bitSize) {
                hashInt = hashInt.shiftRight(hashBits - bitSize);
            }

            // Parse signature
            BigInteger r;
            BigInteger s;
            if (sigType.contains("CVC") || sigType.contains("PLAIN")) {
                BigInteger[] sigPair = PlainDSAEncoding.INSTANCE.decode(n, signature);
                r = sigPair[0];
                s = sigPair[1];
            } else {
                ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(signature);
                r = ((ASN1Integer) seq.getObjectAt(0)).getValue();
                s = ((ASN1Integer) seq.getObjectAt(1)).getValue();
            }


            BigInteger rd = privkey.multiply(r).mod(n);
            BigInteger hrd = hashInt.add(rd).mod(n);
            return s.modInverse(n).multiply(hrd).mod(n);
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

    public static byte[] pubkeyToBytes(PublicKey pubkey) {
        if (pubkey instanceof ECPublicKey) {
            ECPublicKey ecPublicKey = (ECPublicKey) pubkey;
            return ECUtil.toX962Uncompressed(ecPublicKey.getW(), ecPublicKey.getParams());
        } else if (pubkey instanceof XECPublicKey) {
            XECPublicKey xedPublicKey = (XECPublicKey) pubkey;
            return xedPublicKey.getU().toByteArray();
        } else if (pubkey instanceof EdECPublicKey) {
            EdECPublicKey edECPublicKey = (EdECPublicKey) pubkey;
            return edECPublicKey.getPoint().getY().toByteArray();
        } else if (pubkey instanceof XDHPublicKey) {
            XDHPublicKey xdhPublicKey = (XDHPublicKey) pubkey;
            return xdhPublicKey.getU().toByteArray();
            // Special-case BouncyCastle XDH
        } else if (pubkey instanceof EdDSAPublicKey) {
            EdDSAPublicKey edDSAPublicKey = (EdDSAPublicKey) pubkey;
            // Special-case BouncyCastle EdDSA
            return edDSAPublicKey.getPointEncoding();
        }
        return null;
    }

    public static byte[] privkeyToBytes(PrivateKey privkey) {
        if (privkey instanceof ECPrivateKey) {
            ECPrivateKey ecPrivateKey = (ECPrivateKey) privkey;
            return ecPrivateKey.getS().toByteArray();
        } else if (privkey instanceof XECPrivateKey) {
            XECPrivateKey xecPrivateKey = (XECPrivateKey) privkey;
            return xecPrivateKey.getScalar().get();
        } else if (privkey instanceof EdECPrivateKey) {
            EdECPrivateKey edECPrivateKey = (EdECPrivateKey) privkey;
            return edECPrivateKey.getBytes().get();
        } else if (privkey instanceof XDHPrivateKey || privkey instanceof EdDSAPrivateKey) {
            // Special-case BouncyCastle XDH and EdDSA
            PrivateKeyInfo xpkinfo = PrivateKeyInfo.getInstance(privkey.getEncoded());
            return ASN1OctetString.getInstance(xpkinfo.getPrivateKey().getOctets()).getOctets();
        }
        return null;
    }

    public static boolean equalKeyPairParameters(ECPrivateKey priv, ECPublicKey pub) {
        if (priv == null || pub == null) {
            return false;
        }
        return priv.getParams().getCurve().equals(pub.getParams().getCurve()) &&
                priv.getParams().getCofactor() == pub.getParams().getCofactor() &&
                priv.getParams().getGenerator().equals(pub.getParams().getGenerator()) &&
                priv.getParams().getOrder().equals(pub.getParams().getOrder());
    }

    public static boolean equalECParameterSpec(ECParameterSpec left, ECParameterSpec right) {
        if (left == null || right == null) {
            return false;
        }

        return left.getCofactor() == right.getCofactor() &&
                left.getCurve().equals(right.getCurve()) &&
                left.getGenerator().equals(right.getGenerator()) &&
                left.getOrder().equals(right.getOrder());
    }
}
