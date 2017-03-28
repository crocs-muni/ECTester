package cz.crcs.ectester.reader.ec;

import cz.crcs.ectester.reader.Util;

import java.io.*;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Pattern;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class EC_Data {
    private static final Pattern hex = Pattern.compile("(0x|0X)?[a-fA-F\\d]+");

    int count;
    byte[][] data;

    EC_Data() {
    }

    public EC_Data(int count) {
        this.count = count;
        this.data = new byte[count][];
    }

    public EC_Data(byte[][] data) {
        this.count = data.length;
        this.data = data;
    }

    public int getCount() {
        return count;
    }

    public byte[][] getData() {
        return data;
    }

    public boolean hasData() {
        return data != null;
    }

    public byte[] getParam(int index) {
        return data[index];
    }

    public byte[] flatten() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] param : data) {
            byte[] length = new byte[2];
            Util.setShort(length, 0, (short) param.length);

            out.write(length, 0, 2);
            out.write(param, 0, param.length);
        }

        return out.toByteArray();
    }

    public String[] expand() {
        List<String> out = new ArrayList<>(count);
        for (byte[] param : data) {
            out.add(Util.bytesToHex(param, false));
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

    private static byte[] parse(String param) {
        byte[] data;
        if (param.startsWith("0x") || param.startsWith("0X")) {
            data = Util.hexToBytes(param.substring(2));
        } else {
            data = Util.hexToBytes(param);
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

        s.useDelimiter(",|;");
        List<String> data = new LinkedList<>();
        while (s.hasNext()) {
            String field = s.next();
            data.add(field.replaceAll("\\s+", ""));
        }

        if (data.isEmpty()) {
            return false;
        }
        for (String param : data) {
            if (!hex.matcher(param).matches()) {
                return false;
            }
        }
        return readHex(data.toArray(new String[data.size()]));
    }

    public boolean readBytes(byte[] data) {
        //TODO
        return false;
    }

    public void writeCSV(OutputStream out) throws IOException {
        String[] hex = expand();
        Writer w = new OutputStreamWriter(out);
        for (int i = 0; i < hex.length; ++i) {
            w.write(hex[i]);
            if (i < hex.length - 1) {
                w.write(",");
            }
        }
        w.flush();
    }
}
