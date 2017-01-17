package cz.crcs.ectester.reader;

import cz.crcs.ectester.applet.EC_Consts;

import java.io.*;
import java.util.LinkedList;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Pattern;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class ParamReader {
    private static final Pattern hex = Pattern.compile("[a-fA-F\\d]+");

    /**
     * Flattens params read from String[] data into a byte[] with their lengths prepended as short entries.
     * @param params (EC_Consts.PARAMETER_* | ...)
     * @param data data read by readString, readFile, readResource
     * @return byte[] with params flattened
     */
    public static byte[] flatten(short params, String[] data) {
        if (!validate(data)) {
            return null;
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        short paramMask = EC_Consts.PARAMETER_FP;
        int i = 0;
        while (paramMask <= EC_Consts.PARAMETER_S) {
            short masked = (short) (params & paramMask);
            if (masked != 0) {
                byte[] param = parse(data[i]);
                if (masked == EC_Consts.PARAMETER_F2M && data.length == 9) {
                    //read and pad and append e_2, e_3
                    param = Util.concatenate(param, parse(data[i + 1]), parse(data[i + 2]));
                    i += 2;
                    if (param.length != 6)
                        return null;
                }
                if (masked == EC_Consts.PARAMETER_G || masked == EC_Consts.PARAMETER_W) {
                    //read another param (the y coord) and put into X962 format.
                    byte[] y = parse(data[i + 1]);
                    param = Util.concatenate(new byte[]{4}, param, y);
                    i++;
                }
                if (param.length == 0)
                    return null;

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

    /**
     * Reads hex params from a CSV String data.
     * @param data String containing CSV data(hex)
     * @return String array containing the CSV entries
     */
    public static String[] readString(String data) {
        return read(new ByteArrayInputStream(data.getBytes()));
    }

    /**
     * Reads hex params from a CSV Resource (inside jar).
     * @param resourcePath path to the resourse
     * @return String array containing the CSV entries
     */
    public static String[] readResource(String resourcePath) {
        return read(ParamReader.class.getResourceAsStream(resourcePath));
    }

    /**
     * Reads hex params from a CSV file.
     * @param filePath path to the file
     * @return String array containing the CSV entries
     * @throws FileNotFoundException if the file cannot be opened
     */
    public static String[] readFile(String filePath) throws FileNotFoundException {
        return read(new FileInputStream(filePath));
    }

    private static String[] read(InputStream in) {
        Scanner s = new Scanner(in);

        s.useDelimiter(",|;");
        List<String> data = new LinkedList<String>();
        while (s.hasNext()) {
            String field = s.next();
            data.add(field.replaceAll("\\s+", ""));
        }
        return data.toArray(new String[data.size()]);
    }

    private static boolean validate(String[] data) {
        if (data == null || data.length == 0) {
            return false;
        }
        for (String param : data) {
            if (!hex.matcher(param).matches()) {
                return false;
            }
        }
        return true;
    }

    private static byte[] parse(String hex) {
        byte[] data = Util.hexToBytes(hex);
        if (data == null)
            return new byte[0];
        if (data.length < 2)
            return pad(data);
        return data;
    }

    private static byte[] pad(byte[] data) {
        if (data.length == 1) {
            return new byte[]{(byte) 0, data[0]};
        } else if (data.length == 0 || data.length > 2) {
            return data;
        }
        return null;
    }
}