package cz.crcs.ectester.common.ec;

import cz.crcs.ectester.common.util.ByteUtil;

import java.io.*;
import java.util.*;
import java.util.regex.Pattern;

/**
 * A list of byte arrays for holding EC data.
 * <p>
 * The data can be read from a byte array via <code>readBytes()</code>, from a CSV via <code>readCSV()</code>.
 * The data can be exported to a byte array via <code>flatten()</code> or to a string array via <code>expand()</code>.
 *
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class EC_Data implements Comparable<EC_Data> {
    String id;
    int count;
    byte[][] data;

    private static final Pattern HEX = Pattern.compile("(0x|0X)?[a-fA-F\\d]+");

    EC_Data() {
    }

    EC_Data(int count) {
        this.count = count;
        this.data = new byte[count][];
    }

    EC_Data(byte[][] data) {
        this.count = data.length;
        this.data = data;
    }

    EC_Data(String id, int count) {
        this(count);
        this.id = id;
    }

    EC_Data(String id, byte[][] data) {
        this(data);
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public int getCount() {
        return count;
    }

    public byte[][] getData() {
        return data;
    }

    public byte[] getData(int index) {
        return data[index];
    }

    public boolean hasData() {
        return data != null;
    }

    public byte[] flatten() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] param : data) {
            byte[] length = new byte[2];
            ByteUtil.setShort(length, 0, (short) param.length);

            out.write(length, 0, 2);
            out.write(param, 0, param.length);
        }

        return out.toByteArray();
    }

    public String[] expand() {
        List<String> out = new ArrayList<>(count);
        for (byte[] param : data) {
            out.add(ByteUtil.bytesToHex(param, false));
        }

        return out.toArray(new String[out.size()]);
    }

    private static byte[] pad(byte[] data) {
        if (data.length == 1) {
            return new byte[]{(byte) 0, data[0]};
        } else if (data.length == 0 || data.length > 2) {
            return data;
        }
        return null;
    }

    protected static byte[] parse(String param) {
        byte[] data;
        if (param.startsWith("0x") || param.startsWith("0X")) {
            data = ByteUtil.hexToBytes(param.substring(2));
        } else {
            data = ByteUtil.hexToBytes(param);
        }
        if (data == null)
            return new byte[0];
        if (data.length < 2)
            return pad(data);
        return data;
    }

    private boolean readHex(String[] hex) {
        if (hex.length != count) {
            return false;
        }

        for (int i = 0; i < count; ++i) {
            this.data[i] = parse(hex[i]);
        }
        return true;
    }

    public boolean readCSV(InputStream in) {
        Scanner s = new Scanner(in);

        s.useDelimiter("[,;]");
        List<String> data = new LinkedList<>();
        while (s.hasNext()) {
            String field = s.next();
            data.add(field.replaceAll("\\s+", ""));
        }

        if (data.isEmpty()) {
            return false;
        }
        for (String param : data) {
            if (!HEX.matcher(param).matches()) {
                return false;
            }
        }
        return readHex(data.toArray(new String[data.size()]));
    }

    public boolean readBytes(byte[] bytes) {
        if (bytes == null) {
            return false;
        }

        int offset = 0;
        for (int i = 0; i < count; i++) {
            if (bytes.length - offset < 2) {
                return false;
            }
            short paramLength = ByteUtil.getShort(bytes, offset);
            offset += 2;
            if (bytes.length < offset + paramLength) {
                return false;
            }
            data[i] = new byte[paramLength];
            System.arraycopy(bytes, offset, data[i], 0, paramLength);
            offset += paramLength;
        }
        return true;
    }

    public boolean readByteArray(byte[][] bytes) {
        if (bytes == null || count != bytes.length) {
            return false;
        }

        for (int i = 0; i < count; ++i) {
            data[i] = new byte[bytes[i].length];
            System.arraycopy(bytes[i], 0, data[i], 0, bytes[i].length);
        }
        return true;
    }

    public void writeCSV(OutputStream out) throws IOException {
        Writer w = new OutputStreamWriter(out);
        w.write(String.join(",", expand()));
        w.flush();
    }

    @Override
    public String toString() {
        return String.join(",", expand());
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof EC_Data) {
            EC_Data other = (EC_Data) obj;
            if (this.id != null || other.id != null) {
                return Objects.equals(this.id, other.id);
            }

            if (this.count != other.count)
                return false;
            for (int i = 0; i < this.count; ++i) {
                if (!Arrays.equals(this.data[i], other.data[i])) {
                    return false;
                }
            }
            return true;
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        if (this.id != null) {
            return this.id.hashCode();
        }
        return Arrays.deepHashCode(this.data);
    }

    @Override
    public int compareTo(EC_Data o) {
        if (o == this) return 0;
        if (this.id != null && o.id != null) {

            int minLength = Math.min(this.id.length(), o.id.length());
            for (int i = 0; i < minLength; i++) {
                if (this.id.charAt(i) != o.id.charAt(i)) {
                    String thisEnd = this.id.substring(i);
                    String oEnd = o.id.substring(i);
                    try {
                        int thisIndex = Integer.parseInt(thisEnd);
                        int oIndex = Integer.parseInt(oEnd);
                        return Integer.compare(thisIndex, oIndex);
                    } catch (NumberFormatException ignored) {
                        break;
                    }
                }
            }
            return this.id.compareTo(o.id);
        } else if (this.id == null && o.id == null) {
            if (Arrays.equals(this.data, o.data)) {
                return 0;
            } else {
                int minCount = (this.count < o.count) ? this.count : o.count;
                for (int i = 0; i < minCount; ++i) {
                    byte[] thisData = this.data[i];
                    byte[] oData = o.data[i];
                    int innerMinCount = (thisData.length < oData.length) ? thisData.length : oData.length;
                    for (int j = 0; j < innerMinCount; ++j) {
                        if (thisData[j] < oData[j]) {
                            return -1;
                        } else if (thisData[j] > oData[j]) {
                            return 1;
                        }
                    }
                }
            }
        } else {
            if (this.id == null) {
                return -1;
            } else {
                return 1;
            }
        }
        return 0;
    }
}
