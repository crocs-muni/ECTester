package cz.crcs.ectester.common.ec;

import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.util.ByteUtil;
import javacard.security.KeyPair;

import java.math.BigInteger;
import java.security.spec.*;

/**
 * An Elliptic curve, contains parameters Fp/F2M, A, B, G, R, (K)?.
 *
 * @author Jan Jancar johny@neuromancer.sk
 */
public class EC_Curve extends EC_Params {
    private short bits;
    private byte field;
    private String desc;

    /**
     * @param bits
     * @param field KeyPair.ALG_EC_FP or KeyPair.ALG_EC_F2M
     */
    public EC_Curve(short bits, byte field) {
        super(field == KeyPair.ALG_EC_FP ? EC_Consts.PARAMETERS_DOMAIN_FP : EC_Consts.PARAMETERS_DOMAIN_F2M);
        this.bits = bits;
        this.field = field;
    }

    public EC_Curve(String id, short bits, byte field) {
        this(bits, field);
        this.id = id;
    }

    public EC_Curve(String id, short bits, byte field, String desc) {
        this(id, bits, field);
        this.desc = desc;
    }

    public short getBits() {
        return bits;
    }

    public byte getField() {
        return field;
    }

    public String getDesc() {
        return desc;
    }

    @Override
    public String toString() {
        return "<" + getId() + "> " + (field == KeyPair.ALG_EC_FP ? "Prime" : "Binary") + " field Elliptic curve (" + String.valueOf(bits) + "b)" + (desc == null ? "" : ": " + desc);
    }

    public EllipticCurve toCurve() {
        ECField field;
        if (this.field == KeyPair.ALG_EC_FP) {
            field = new ECFieldFp(new BigInteger(1, getData(0)));
        } else {
            byte[][] fieldData = getParam(EC_Consts.PARAMETER_F2M);
            int m = ByteUtil.getShort(fieldData[0], 0);
            int e1 = ByteUtil.getShort(fieldData[1], 0);
            int e2 = ByteUtil.getShort(fieldData[2], 0);
            int e3 = ByteUtil.getShort(fieldData[3], 0);
            int[] powers = new int[]{e1, e2, e3};
            field = new ECFieldF2m(m, powers);
        }

        BigInteger a = new BigInteger(1, getParam(EC_Consts.PARAMETER_A)[0]);
        BigInteger b = new BigInteger(1, getParam(EC_Consts.PARAMETER_B)[0]);

        return new EllipticCurve(field, a, b);
    }

    public ECParameterSpec toSpec() {
        EllipticCurve curve = toCurve();

        byte[][] G = getParam(EC_Consts.PARAMETER_G);
        BigInteger gx = new BigInteger(1, G[0]);
        BigInteger gy = new BigInteger(1, G[1]);
        ECPoint generator = new ECPoint(gx, gy);

        BigInteger n = new BigInteger(1, getParam(EC_Consts.PARAMETER_R)[0]);

        int h = ByteUtil.getShort(getParam(EC_Consts.PARAMETER_K)[0], 0);

        return new ECParameterSpec(curve, generator, n, h);
    }

    public static EC_Curve fromSpec(ECParameterSpec spec) {
        EllipticCurve curve = spec.getCurve();
        ECField field = curve.getField();

        short bits = (short) field.getFieldSize();
        byte[][] params;
        int paramIndex = 0;
        byte fieldType;
        if (field instanceof ECFieldFp) {
            ECFieldFp primeField = (ECFieldFp) field;
            params = new byte[7][];
            params[paramIndex++] = primeField.getP().toByteArray();
            fieldType = KeyPair.ALG_EC_FP;
        } else if (field instanceof ECFieldF2m) {
            ECFieldF2m binaryField = (ECFieldF2m) field;
            params = new byte[10][];
            params[paramIndex] = new byte[2];
            ByteUtil.setShort(params[paramIndex++], 0, (short) binaryField.getM());
            int[] powers = binaryField.getMidTermsOfReductionPolynomial();
            for (int i = 0; i < 3; ++i) {
                params[paramIndex] = new byte[2];
                ByteUtil.setShort(params[paramIndex++], 0, (short) powers[i]);
            }
            fieldType = KeyPair.ALG_EC_F2M;
        } else {
            throw new IllegalArgumentException("ECParameterSpec with an unknown field.");
        }

        ECPoint generator = spec.getGenerator();

        params[paramIndex++] = curve.getA().toByteArray();
        params[paramIndex++] = curve.getB().toByteArray();

        params[paramIndex++] = generator.getAffineX().toByteArray();
        params[paramIndex++] = generator.getAffineY().toByteArray();

        params[paramIndex++] = spec.getOrder().toByteArray();
        params[paramIndex] = new byte[2];
        ByteUtil.setShort(params[paramIndex], 0, (short) spec.getCofactor());

        EC_Curve result = new EC_Curve(bits, fieldType);
        result.readByteArray(params);
        return result;
    }
}
