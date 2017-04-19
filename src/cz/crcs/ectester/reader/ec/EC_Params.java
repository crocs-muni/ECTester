package cz.crcs.ectester.reader.ec;

import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.reader.Util;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class EC_Params extends EC_Data {
    private short params;

    public EC_Params(short params) {
        this.params = params;
        this.count = numParams();
        this.data = new byte[this.count][];
    }

    public EC_Params(short params, byte[][] data) {
        this.params = params;
        this.count = data.length;
        this.data = data;
    }

    public EC_Params(String id, short params) {
        this(params);
        this.id = id;
    }

    public EC_Params(String id, short params, byte[][] data) {
        this(params, data);
        this.id = id;
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
                if (paramMask == EC_Consts.PARAMETER_W || paramMask == EC_Consts.PARAMETER_G) {
                    num += 1;
                }
                ++num;
            }
            paramMask = (short) (paramMask << 1);
        }
        return num;
    }

    @Override
    public byte[] flatten() {
        return flatten(params);
    }

    public byte[] flatten(short params) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        short paramMask = EC_Consts.PARAMETER_FP;
        int i = 0;
        while (paramMask <= EC_Consts.PARAMETER_S) {
            short masked = (short) (this.params & params & paramMask);
            short shallow = (short) (this.params & paramMask);
            if (masked != 0) {
                byte[] param = data[i];
                if (masked == EC_Consts.PARAMETER_F2M) {
                    //add m, e_1, e_2, e_3
                    param = Util.concatenate(param, data[i + 1]);
                    if (!Util.allValue(data[i + 2], (byte) 0)) {
                        param = Util.concatenate(param, data[i + 2]);
                    }
                    if (!Util.allValue(data[i + 3], (byte) 0)) {
                        param = Util.concatenate(param, data[i + 3]);
                    }
                    if (!(param.length == 4 || param.length == 8))
                        throw new RuntimeException("PARAMETER_F2M length is not 8.(should be)");
                }
                if (masked == EC_Consts.PARAMETER_G || masked == EC_Consts.PARAMETER_W) {
                    //read another param (the y coord) and put into X962 format.
                    byte[] y = data[i + 1];
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
            }
            if (shallow == EC_Consts.PARAMETER_F2M) {
                i += 4;
            } else if (shallow == EC_Consts.PARAMETER_G || shallow == EC_Consts.PARAMETER_W) {
                i += 2;
            } else if (shallow != 0) {
                i++;
            }
            paramMask = (short) (paramMask << 1);
        }

        return (out.size() == 0) ? null : out.toByteArray();
    }

    @Override
    public String[] expand() {
        List<String> out = new ArrayList<>();

        short paramMask = EC_Consts.PARAMETER_FP;
        int index = 0;
        while (paramMask <= EC_Consts.PARAMETER_S) {
            short masked = (short) (params & paramMask);
            if (masked != 0) {
                byte[] param = data[index];
                if (masked == EC_Consts.PARAMETER_F2M) {
                    for (int i = 0; i < 4; ++i) {
                        out.add(Util.bytesToHex(data[index + i], false));
                    }
                    index += 4;
                } else if (masked == EC_Consts.PARAMETER_G || masked == EC_Consts.PARAMETER_W) {
                    out.add(Util.bytesToHex(param, false));
                    out.add(Util.bytesToHex(data[index + 1], false));
                    index += 2;
                } else {
                    out.add(Util.bytesToHex(param, false));
                    index++;
                }
            }
            paramMask = (short) (paramMask << 1);
        }
        return out.toArray(new String[out.size()]);
    }
}
