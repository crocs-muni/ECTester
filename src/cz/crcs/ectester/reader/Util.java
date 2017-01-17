package cz.crcs.ectester.reader;

/**
 * @author Petr Svenda petr@svenda.com
 * @author Jan Jancar johny@neuromancer.sk
 */
public class Util {

    public static short getShort(byte[] array, int offset) {
        return (short) (((array[offset] & 0xFF) << 8) | (array[offset + 1] & 0xFF));
    }

    public static void setShort(byte[] array, int offset, short value) {
        array[offset + 1] = (byte) (value & 0xFF);
        array[offset] = (byte) ((value >> 8) & 0xFF);
    }

    public static byte[] hexToBytes(String hex) {
        return hexToBytes(hex, true);
    }

    public static byte[] hexToBytes(String hex, boolean bigEndian) {
        StringBuilder sb = new StringBuilder(hex.replace(" ", ""));
        if (!bigEndian) {
            sb.reverse();
        }
        int len = sb.length();
        if (len % 2 == 1) {
            sb.insert(0, "0");
            ++len;
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
        return bytesToHex(data, 0, data.length, true);
    }

    public static String bytesToHex(byte[] data, int offset, int len) {
        return bytesToHex(data, offset, len, true);
    }

    public static String bytesToHex(byte[] data, int offset, int len, boolean bAddSpace) {
        StringBuilder buf = new StringBuilder();
        for (int i = offset; i < (offset + len); i++) {
            buf.append(byteToHex(data[i]));
            if (bAddSpace && i != (offset + len - 1)) {
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
}
