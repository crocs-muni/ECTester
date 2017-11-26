package cz.crcs.ectester.common.util;

import java.math.BigInteger;
import java.security.spec.ECPoint;

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
}
