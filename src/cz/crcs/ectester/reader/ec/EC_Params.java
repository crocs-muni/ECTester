package cz.crcs.ectester.reader.ec;

import cz.crcs.ectester.applet.EC_Consts;
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
public class EC_Params {
    private static final Pattern hex = Pattern.compile("(0x|0X)?[a-fA-F\\d]+");

    private short params;
    private byte[][] data;

    public EC_Params(short params) {
        this.params = params;
        this.data = new byte[numParams()][];
    }

    public EC_Params(short params, byte[][] data) {
        this.params = params;
        this.data = data;
    }

    public short getParams() {
        return params;
    }

    public boolean hasParam(short param) {
        return (params & param) != 0;
    }

    public int numParams() {
        short paramMask = EC_Consts.PARAMETER_FP;
        int num = 0;
        while (paramMask <= EC_Consts.PARAMETER_S) {
            if ((paramMask & params) != 0) {
                if (paramMask == EC_Consts.PARAMETER_F2M) {
                    num += 3;
                }
                if (paramMask == EC_Consts.PARAMETER_W || paramMask == EC_Consts.PARAMETER_G){
                    num += 1;
                }
                ++num;
            }
            paramMask = (short) (paramMask << 1);
        }
        return num;
    }

    public byte[][] getData() {
        return data;
    }

    public boolean hasData() {
        return data != null;
    }

    public byte[] flatten() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        short paramMask = EC_Consts.PARAMETER_FP;
        int i = 0;
        while (paramMask <= EC_Consts.PARAMETER_S) {
            short masked = (short) (params & paramMask);
            if (masked != 0) {
                byte[] param = data[i];
                if (masked == EC_Consts.PARAMETER_F2M) {
                    //add m, e_1, e_2, e_3
                    param = Util.concatenate(param, data[i + 1], data[i + 2], data[i + 3]);
                    i += 3;
                    if (param.length != 8)
                        throw new RuntimeException("PARAMETER_F2M length is not 8.(should be)");
                }
                if (masked == EC_Consts.PARAMETER_G || masked == EC_Consts.PARAMETER_W) {
                    //read another param (the y coord) and put into X962 format.
                    byte[] y = data[++i];
                    param = Util.concatenate(new byte[]{4}, param, y); //<- ugly but works!
                }
                if (param.length == 0)
                    throw new RuntimeException("Empty parameter read?");

                //write length
                byte[] length = new byte[2];
                Util.setShort(length, 0, (short) param.length);
                out.write(length, 0, 2);
                //write data
                out.write(param, 0, param.length);
                i++;
            }
            paramMask = (short) (paramMask << 1);
        }

        return (out.size() == 0) ? null : out.toByteArray();
    }

    public String[] expand() {
        List<String> out = new ArrayList<>();

        short paramMask = EC_Consts.PARAMETER_FP;
        int index = 0;
        while (paramMask <= EC_Consts.PARAMETER_S) {
            short masked = (short) (params & paramMask);
            if (masked != 0) {
                byte[] param = data[index];

                if (masked == EC_Consts.PARAMETER_F2M) {
                    //split into m, e1, e2, e3
                    if (param.length != 8) {
                        throw new RuntimeException("PARAMETER_F2M length is not 8.(should be)");
                    }
                    for (int i = 0; i < 4; ++i) {
                        out.add(String.format("%04x", Util.getShort(param, i * 2)));
                    }

                } else if (masked == EC_Consts.PARAMETER_G || masked == EC_Consts.PARAMETER_W) {
                    //split from X962 format into X and Y
                    //disregard the first 04 and then split into half(uncompress)
                    int half = (param.length - 1) / 2;
                    out.add(Util.bytesToHex(param, 1, half, false));
                    out.add(Util.bytesToHex(param, half + 1, half, false));
                } else {
                    //read raw
                    out.add(Util.bytesToHex(data[index], false));
                }
                index++;
            }
            paramMask = (short) (paramMask << 1);
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
        if (hex.length != numParams()) {
            return false;
        }

        for (int i = 0; i < numParams(); ++i) {
            this.data[i] = parse(hex[i]);
        }
        return true;
    }

    public boolean readCSV(InputStream in) {
        Scanner s = new Scanner(in);

        s.useDelimiter(",|;");
        List<String> data = new LinkedList<String>();
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

    public boolean readBytes(byte[] data) {
        //TODO
        return false;
    }
}
