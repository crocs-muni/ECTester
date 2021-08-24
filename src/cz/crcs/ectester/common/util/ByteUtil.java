package cz.crcs.ectester.common.util;

/**
 * Utility class, some byte/hex manipulation, convenient byte[] methods.
 *
 * @author Petr Svenda petr@svenda.com
 * @author Jan Jancar johny@neuromancer.sk
 */
public class ByteUtil {

    /**
     * Get a short from a byte array at <code>offset</code>, big-endian.
     *
     * @return the short value
     */
    public static short getShort(byte[] array, int offset) {
        return (short) (((array[offset] & 0xFF) << 8) | (array[offset + 1] & 0xFF));
    }

    /**
     * Get a short from a byte array at <code>offset</code>, return it as an int, big-endian.
     *
     * @return the short value (as an int)
     */
    public static int getShortInt(byte[] array, int offset) {
        return (((array[offset] & 0xFF) << 8) | (array[offset + 1] & 0xFF));
    }

    /**
     * Set a short in a byte array at <code>offset</code>, big-endian.
     */
    public static void setShort(byte[] array, int offset, short value) {
        array[offset + 1] = (byte) (value & 0xFF);
        array[offset] = (byte) ((value >> 8) & 0xFF);
    }

    /**
     * Compare two byte arrays upto <code>length</code> and get first difference.
     *
     * @return the position of the first difference in the two byte arrays, or <code>length</code> if they are equal.
     */
    public static int diffBytes(byte[] one, int oneOffset, byte[] other, int otherOffset, int length) {
        for (int i = 0; i < length; ++i) {
            byte a = one[i + oneOffset];
            byte b = other[i + otherOffset];
            if (a != b) {
                return i;
            }
        }
        return length;
    }

    /**
     * Compare two byte arrays, upto <code>length</code>.
     *
     * @return whether the arrays are equal upto <code>length</code>
     */
    public static boolean compareBytes(byte[] one, int oneOffset, byte[] other, int otherOffset, int length) {
        return diffBytes(one, oneOffset, other, otherOffset, length) == length;
    }

    /**
     * Test if the byte array has all values equal to <code>value</code>.
     */
    public static boolean allValue(byte[] array, byte value) {
        for (byte a : array) {
            if (a != value)
                return false;
        }
        return true;
    }

    public static byte[] shortToBytes(short value) {
        byte[] result = new byte[2];
        setShort(result, 0, value);
        return result;
    }

    public static byte[] shortToBytes(short[] shorts) {
        if (shorts == null) {
            return null;
        }
        byte[] result = new byte[shorts.length * 2];
        for (int i = 0; i < shorts.length; ++i) {
            setShort(result, 2 * i, shorts[i]);
        }
        return result;
    }

    /**
     * Parse a hex string into a byte array, big-endian.
     *
     * @param hex The String to parse.
     * @return the byte array from the hex string.
     */
    public static byte[] hexToBytes(String hex) {
        return hexToBytes(hex, true);
    }

    /**
     * Parse a hex string into a byte-array, specify endianity.
     *
     * @param hex       The String to parse.
     * @param bigEndian Whether to parse as big-endian.
     * @return the byte array from the hex string.
     */
    public static byte[] hexToBytes(String hex, boolean bigEndian) {
        hex = hex.replace(" ", "");
        int len = hex.length();
        StringBuilder sb = new StringBuilder();

        if (len % 2 == 1) {
            sb.append("0");
            ++len;
        }

        if (bigEndian) {
            sb.append(hex);
        } else {
            for (int i = 0; i < len / 2; ++i) {
                if (sb.length() >= 2) {
                    sb.insert(sb.length() - 2, hex.substring(2 * i, 2 * i + 2));
                } else {
                    sb.append(hex.substring(2 * i, 2 * i + 2));
                }

            }
        }

        String data = sb.toString();
        byte[] result = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            result[i / 2] = (byte) ((Character.digit(data.charAt(i), 16) << 4)
                    + (Character.digit(data.charAt(i + 1), 16)));
        }
        return result;
    }

    public static String byteToHex(byte data) {
        return String.format("%02x", data);
    }

    public static String bytesToHex(byte[] data) {
        return bytesToHex(data, true);
    }

    public static String bytesToHex(byte[] data, boolean addSpace) {
        if (data == null) {
            return "";
        }
        return bytesToHex(data, 0, data.length, addSpace);
    }

    public static String bytesToHex(byte[] data, int offset, int len) {
        return bytesToHex(data, offset, len, true);
    }

    public static String bytesToHex(byte[] data, int offset, int len, boolean addSpace) {
        if (data == null) {
            return "";
        }
        StringBuilder buf = new StringBuilder();
        for (int i = offset; i < (offset + len); i++) {
            buf.append(byteToHex(data[i]));
            if (addSpace && i != (offset + len - 1)) {
                buf.append(" ");
            }
        }
        return (buf.toString());
    }

    public static byte[] concatenate(byte[]... arrays) {
        int len = 0;
        for (byte[] array : arrays) {
            if (array == null)
                continue;
            len += array.length;
        }
        byte[] out = new byte[len];
        int offset = 0;
        for (byte[] array : arrays) {
            if (array == null || array.length == 0)
                continue;
            System.arraycopy(array, 0, out, offset, array.length);
            offset += array.length;
        }
        return out;
    }

    public static byte[] prependLength(byte[] data) {
        return concatenate(ByteUtil.shortToBytes((short) data.length), data);
    }
}
