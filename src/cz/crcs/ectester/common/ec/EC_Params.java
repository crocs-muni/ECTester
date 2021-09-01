package cz.crcs.ectester.common.ec;

import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.util.ByteUtil;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * A list of EC parameters, can contain a subset of the Fp/F2M, A, B, G, R, K, W, S parameters.
 * <p>
 * The set of parameters is uniquely identified by a short bit string.
 * The parameters can be exported to a byte array via <code>flatten()</code> or to a comma delimited
 * string via <code>expand()</code>.
 *
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

    public byte[][] getParam(short param) {
        if (!hasParam(param)) {
            return null;
        }
        if (Integer.bitCount(param) != 1) {
            return null;
        }
        short paramMask = EC_Consts.PARAMETER_FP;
        byte[][] result = null;
        int i = 0;
        while (paramMask <= EC_Consts.PARAMETER_S) {
            short masked = (short) (this.params & param & paramMask);
            short shallow = (short) (this.params & paramMask);
            if (masked != 0) {
                if (masked == EC_Consts.PARAMETER_F2M) {
                    result = new byte[4][];
                    result[0] = data[i].clone();
                    result[1] = data[i + 1].clone();
                    result[2] = data[i + 2].clone();
                    result[3] = data[i + 3].clone();
                    break;
                }
                if (masked == EC_Consts.PARAMETER_G || masked == EC_Consts.PARAMETER_W) {
                    result = new byte[2][];
                    result[0] = data[i].clone();
                    result[1] = data[i + 1].clone();
                    break;
                }
                result = new byte[1][];
                result[0] = data[i].clone();
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
        return result;
    }

    public boolean setParam(short param, byte[][] value) {
        if (!hasParam(param)) {
            return false;
        }
        if (Integer.bitCount(param) != 1) {
            return false;
        }
        short paramMask = EC_Consts.PARAMETER_FP;
        int i = 0;
        while (paramMask <= EC_Consts.PARAMETER_S) {
            short masked = (short) (this.params & param & paramMask);
            short shallow = (short) (this.params & paramMask);
            if (masked != 0) {
                if (masked == EC_Consts.PARAMETER_F2M) {
                    data[i] = value[0];
                    data[i + 1] = value[1];
                    data[i + 2] = value[2];
                    data[i + 3] = value[3];
                    break;
                }
                if (masked == EC_Consts.PARAMETER_G || masked == EC_Consts.PARAMETER_W) {
                    data[i] = value[0];
                    data[i + 1] = value[1];
                    break;
                }
                data[i] = value[0];
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
        return true;
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
                    param = ByteUtil.concatenate(param, data[i + 1]);
                    if (!ByteUtil.allValue(data[i + 2], (byte) 0)) {
                        param = ByteUtil.concatenate(param, data[i + 2]);
                    }
                    if (!ByteUtil.allValue(data[i + 3], (byte) 0)) {
                        param = ByteUtil.concatenate(param, data[i + 3]);
                    }
                    if (!(param.length == 4 || param.length == 8))
                        throw new RuntimeException("PARAMETER_F2M length is not 8.(should be)");
                }
                if (masked == EC_Consts.PARAMETER_G || masked == EC_Consts.PARAMETER_W) {
                    //read another param (the y coord) and put into X962 format.
                    byte[] y = data[i + 1];
                    param = ByteUtil.concatenate(new byte[]{4}, param, y); //<- ugly but works!
                }
                if (param.length == 0)
                    throw new RuntimeException("Empty parameter read?");

                //write length
                byte[] length = new byte[2];
                ByteUtil.setShort(length, 0, (short) param.length);
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
                        out.add(ByteUtil.bytesToHex(data[index + i], false));
                    }
                    index += 4;
                } else if (masked == EC_Consts.PARAMETER_G || masked == EC_Consts.PARAMETER_W) {
                    out.add(ByteUtil.bytesToHex(param, false));
                    out.add(ByteUtil.bytesToHex(data[index + 1], false));
                    index += 2;
                } else {
                    out.add(ByteUtil.bytesToHex(param, false));
                    index++;
                }
            }
            paramMask = (short) (paramMask << 1);
        }
        return out.toArray(new String[0]);
    }
}
