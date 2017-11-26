package cz.crcs.ectester.reader.response;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.util.ByteUtil;
import cz.crcs.ectester.common.util.CardUtil;
import javacard.framework.ISO7816;
import javacard.security.KeyPair;

import javax.smartcardio.ResponseAPDU;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class Response {

    private ResponseAPDU resp;
    private long time;
    private short[] sws;
    private int numSW = 0;
    private byte[][] params;
    private boolean success = true;
    private boolean error = false;

    public Response(ResponseAPDU response, long time) {
        this.resp = response;
        this.time = time;
    }

    void parse(int numSW, int numParams) {
        this.numSW = numSW;
        this.sws = new short[numSW];

        byte[] data = resp.getData();
        int offset = 0;

        //parse SWs in response
        for (int i = 0; i < numSW; ++i) {
            if (getLength() >= (offset + 2)) {
                short sw = ByteUtil.getShort(data, offset);
                offset += 2;
                sws[i] = sw;
                if (sw != ISO7816.SW_NO_ERROR) {
                    success = false;
                }
            } else {
                success = false;
                error = true;
            }
        }

        if ((short) resp.getSW() != ISO7816.SW_NO_ERROR) {
            success = false;
            error = true;
        }


        //try to parse numParams..
        params = new byte[numParams][];
        for (int i = 0; i < numParams; i++) {
            if (data.length - offset < 2) {
                success = false;
                error = true;
                break;
            }
            short paramLength = ByteUtil.getShort(data, offset);
            offset += 2;
            if (data.length < offset + paramLength) {
                error = true;
                success = false;
                break;
            }
            params[i] = new byte[paramLength];
            System.arraycopy(data, offset, params[i], 0, paramLength);
            offset += paramLength;
        }
    }

    public ResponseAPDU getAPDU() {
        return resp;
    }

    public long getDuration() {
        return time;
    }

    public short getNaturalSW() {
        return (short) resp.getSW();
    }

    public short getSW(int index) {
        return sws[index];
    }

    public int getNumSW() {
        return numSW;
    }

    public boolean hasParam(int index) {
        return params.length >= index + 1 && params[index] != null;
    }

    public int getParamLength(int index) {
        return params[index].length;
    }

    public byte[] getParam(int index) {
        return params[index];
    }

    public byte[][] getParams() {
        return params;
    }

    public int getLength() {
        return resp.getNr();
    }

    public boolean successful() {
        return this.success;
    }

    public boolean error() {
        return this.error;
    }

    public abstract String getDescription();

    /**
     *
     */
    public static class AllocateKeyAgreement extends Response {
        byte kaType;

        public AllocateKeyAgreement(ResponseAPDU response, long time, byte kaType) {
            super(response, time);
            this.kaType = kaType;

            parse(2, 0);
        }

        @Override
        public String getDescription() {
            return String.format("Allocated KeyAgreement(%s) object", CardUtil.getKATypeString(this.kaType));
        }

    }

    public static class Allocate extends Response {

        private byte keyPair;
        private short keyLength;
        private byte keyClass;

        public Allocate(ResponseAPDU response, long time, byte keyPair, short keyLength, byte keyClass) {
            super(response, time);
            this.keyPair = keyPair;
            this.keyLength = keyLength;
            this.keyClass = keyClass;

            int pairs = 0;
            if ((keyPair & ECTesterApplet.KEYPAIR_LOCAL) != 0) pairs++;
            if ((keyPair & ECTesterApplet.KEYPAIR_REMOTE) != 0) pairs++;
            parse(pairs, 0);
        }

        @Override
        public String getDescription() {
            String field = keyClass == KeyPair.ALG_EC_FP ? "ALG_EC_FP" : "ALG_EC_F2M";
            String key;
            if (keyPair == ECTesterApplet.KEYPAIR_BOTH) {
                key = "both keypairs";
            } else {
                key = ((keyPair == ECTesterApplet.KEYPAIR_LOCAL) ? "local" : "remote") + " keypair";
            }
            return String.format("Allocated %s %db %s", key, keyLength, field);
        }
    }

    /**
     *
     */
    public static class Clear extends Response {

        private byte keyPair;

        public Clear(ResponseAPDU response, long time, byte keyPair) {
            super(response, time);
            this.keyPair = keyPair;

            int pairs = 0;
            if ((keyPair & ECTesterApplet.KEYPAIR_LOCAL) != 0) pairs++;
            if ((keyPair & ECTesterApplet.KEYPAIR_REMOTE) != 0) pairs++;
            parse(pairs, 0);
        }

        @Override
        public String getDescription() {
            String key;
            if (keyPair == ECTesterApplet.KEYPAIR_BOTH) {
                key = "both keypairs";
            } else {
                key = ((keyPair == ECTesterApplet.KEYPAIR_LOCAL) ? "local" : "remote") + " keypair";
            }
            return String.format("Cleared %s", key);
        }
    }

    /**
     *
     */
    public static class Set extends Response {

        private byte keyPair;
        private byte curve;
        private short parameters;

        public Set(ResponseAPDU response, long time, byte keyPair, byte curve, short parameters) {
            super(response, time);
            this.keyPair = keyPair;
            this.curve = curve;
            this.parameters = parameters;

            int pairs = 0;
            if ((keyPair & ECTesterApplet.KEYPAIR_LOCAL) != 0) pairs++;
            if ((keyPair & ECTesterApplet.KEYPAIR_REMOTE) != 0) pairs++;

            parse(pairs, 0);
        }

        @Override
        public String getDescription() {
            String name;
            switch (curve) {
                case EC_Consts.CURVE_default:
                    name = "default";
                    break;
                case EC_Consts.CURVE_external:
                    name = "external";
                    break;
                default:
                    name = "custom";
                    break;
            }
            String what = "";
            if (parameters == EC_Consts.PARAMETERS_DOMAIN_F2M || parameters == EC_Consts.PARAMETERS_DOMAIN_FP) {
                what = "curve";
            } else if (parameters == EC_Consts.PARAMETER_W) {
                what = "pubkey";
            } else if (parameters == EC_Consts.PARAMETER_S) {
                what = "privkey";
            } else if (parameters == EC_Consts.PARAMETERS_KEYPAIR) {
                what = "keypair";
            }

            String pair;
            if (keyPair == ECTesterApplet.KEYPAIR_BOTH) {
                pair = "both keypairs";
            } else {
                pair = ((keyPair == ECTesterApplet.KEYPAIR_LOCAL) ? "local" : "remote") + " keypair";
            }
            return String.format("Set %s %s parameters on %s", name, what, pair);
        }

    }

    /**
     *
     */
    public static class Corrupt extends Response {

        private byte keyPair;
        private byte key;
        private short params;
        private byte corruption;

        public Corrupt(ResponseAPDU response, long time, byte keyPair, byte key, short params, byte corruption) {
            super(response, time);
            this.keyPair = keyPair;
            this.key = key;
            this.params = params;
            this.corruption = corruption;

            int pairs = 0;
            if ((keyPair & ECTesterApplet.KEYPAIR_LOCAL) != 0) pairs++;
            if ((keyPair & ECTesterApplet.KEYPAIR_REMOTE) != 0) pairs++;

            parse(pairs, 0);
        }

        @Override
        public String getDescription() {
            String corrupt = CardUtil.getCorruption(corruption);

            String pair;
            if (keyPair == ECTesterApplet.KEYPAIR_BOTH) {
                pair = "both keypairs";
            } else {
                pair = ((keyPair == ECTesterApplet.KEYPAIR_LOCAL) ? "local" : "remote") + " keypair";
            }
            return String.format("Corrupted params of %s, %s", pair, corrupt);
        }
    }

    /**
     *
     */
    public static class Generate extends Response {

        private byte keyPair;

        public Generate(ResponseAPDU response, long time, byte keyPair) {
            super(response, time);
            this.keyPair = keyPair;

            int generated = 0;
            if ((keyPair & ECTesterApplet.KEYPAIR_LOCAL) != 0) generated++;
            if ((keyPair & ECTesterApplet.KEYPAIR_REMOTE) != 0) generated++;
            parse(generated, 0);
        }

        @Override
        public String getDescription() {
            String key;
            if (keyPair == ECTesterApplet.KEYPAIR_BOTH) {
                key = "both keypairs";
            } else {
                key = ((keyPair == ECTesterApplet.KEYPAIR_LOCAL) ? "local" : "remote") + " keypair";
            }
            return String.format("Generated %s", key);
        }

    }

    /**
     *
     */
    public static class Export extends Response {

        private byte keyPair;
        private byte key;
        private short parameters;

        public Export(ResponseAPDU response, long time, byte keyPair, byte key, short parameters) {
            super(response, time);
            this.keyPair = keyPair;
            this.key = key;
            this.parameters = parameters;

            int exported = 0;
            if ((keyPair & ECTesterApplet.KEYPAIR_LOCAL) != 0) exported++;
            if ((keyPair & ECTesterApplet.KEYPAIR_REMOTE) != 0) exported++;
            int keys = 0;
            if ((key & EC_Consts.KEY_PUBLIC) != 0) keys++;
            if ((key & EC_Consts.KEY_PRIVATE) != 0) keys++;
            int paramCount = 0;
            short mask = EC_Consts.PARAMETER_FP;
            while (mask <= EC_Consts.PARAMETER_K) {
                if ((mask & parameters) != 0) {
                    paramCount++;
                }
                mask = (short) (mask << 1);
            }
            int other = 0;
            if ((key & EC_Consts.KEY_PUBLIC) != 0 && (parameters & EC_Consts.PARAMETER_W) != 0) other++;
            if ((key & EC_Consts.KEY_PRIVATE) != 0 && (parameters & EC_Consts.PARAMETER_S) != 0) other++;

            parse(exported, exported * keys * paramCount + exported * other);
        }

        private int getIndex(byte keyPair, short param) {
            byte pair = ECTesterApplet.KEYPAIR_LOCAL;
            int index = 0;
            while (pair <= ECTesterApplet.KEYPAIR_REMOTE) {
                short mask = EC_Consts.PARAMETER_FP;
                while (mask <= EC_Consts.PARAMETER_S) {
                    if (pair == keyPair && param == mask) {
                        return index;
                    }
                    if ((parameters & mask) != 0 && (pair & keyPair) != 0) {
                        if (mask == EC_Consts.PARAMETER_W) {
                            if ((key & EC_Consts.KEY_PUBLIC) != 0)
                                index++;
                        } else if (mask == EC_Consts.PARAMETER_S) {
                            if ((key & EC_Consts.KEY_PRIVATE) != 0)
                                index++;
                        } else {
                            index++;
                        }
                    }
                    mask = (short) (mask << 1);
                }

                pair = (byte) (pair << 1);
            }
            return -1;
        }

        public boolean hasParameters(byte keyPair, short params) {
            if ((keyPair & this.keyPair) == 0 || (params ^ parameters) != 0) {
                return false;
            }
            short param = EC_Consts.PARAMETER_FP;
            while (param <= EC_Consts.PARAMETER_S) {
                short masked = (short) (param & params);
                if (masked != 0 && !hasParameter(keyPair, masked)) {
                    return false;
                }
                param = (short) (param << 1);
            }
            return true;
        }

        public boolean hasParameter(byte keyPair, short param) {
            if ((keyPair & this.keyPair) == 0 || (parameters & param) == 0) {
                return false;
            }
            int index = getIndex(keyPair, param);
            return index != -1 && hasParam(index);
        }

        public byte[] getParameter(byte keyPair, short param) {
            return getParam(getIndex(keyPair, param));
        }

        @Override
        public String getDescription() {
            String source;
            if (key == EC_Consts.KEY_BOTH) {
                source = "both keys";
            } else {
                source = ((key == EC_Consts.KEY_PUBLIC) ? "public" : "private") + " key";
            }
            String pair;
            if (keyPair == ECTesterApplet.KEYPAIR_BOTH) {
                pair = "both keypairs";
            } else {
                pair = ((keyPair == ECTesterApplet.KEYPAIR_LOCAL) ? "local" : "remote") + " keypair";
            }
            return String.format("Exported params from %s of %s", source, pair);
        }
    }

    /**
     *
     */
    public static class ECDH extends Response {

        private byte pubkey;
        private byte privkey;
        private byte export;
        private short corruption;
        private byte type;

        public ECDH(ResponseAPDU response, long time, byte pubkey, byte privkey, byte export, short corruption, byte type) {
            super(response, time);
            this.pubkey = pubkey;
            this.privkey = privkey;
            this.export = export;
            this.corruption = corruption;
            this.type = type;

            parse(1, (export == ECTesterApplet.EXPORT_TRUE) ? 1 : 0);
        }

        public boolean hasSecret() {
            return hasParam(0);
        }

        public byte[] getSecret() {
            return getParam(0);
        }

        public int secretLength() {
            return getParamLength(0);
        }

        @Override
        public String getDescription() {
            String algo = CardUtil.getKA(type);

            String pub = pubkey == ECTesterApplet.KEYPAIR_LOCAL ? "local" : "remote";
            String priv = privkey == ECTesterApplet.KEYPAIR_LOCAL ? "local" : "remote";

            String validity;
            if (corruption == EC_Consts.CORRUPTION_NONE) {
                validity = "unchanged";
            } else {
                validity = CardUtil.getCorruption(corruption);
            }
            return String.format("%s of %s pubkey and %s privkey(%s point)", algo, pub, priv, validity);
        }
    }

    /**
     *
     */
    public static class ECDSA extends Response {

        private byte keyPair;
        private byte export;
        private byte[] raw;

        public ECDSA(ResponseAPDU response, long time, byte keyPair, byte export, byte[] raw) {
            super(response, time);
            this.keyPair = keyPair;
            this.export = export;
            this.raw = raw;

            parse(1, (export == ECTesterApplet.EXPORT_TRUE) ? 1 : 0);
        }

        public boolean hasSignature() {
            return hasParam(0);
        }

        public byte[] getSignature() {
            return getParam(0);
        }

        @Override
        public String getDescription() {
            String key = keyPair == ECTesterApplet.KEYPAIR_LOCAL ? "local" : "remote";
            String data = raw == null ? "random" : "provided";
            return String.format("ECDSA with %s keypair(%s data)", key, data);
        }
    }

    /**
     *
     */
    public static class Cleanup extends Response {

        public Cleanup(ResponseAPDU response, long time) {
            super(response, time);

            parse(1, 0);
        }

        @Override
        public String getDescription() {
            return "Requested JCSystem object deletion";
        }

    }

    /**
     *
     */
    public static class Support extends Response {

        public Support(ResponseAPDU response, long time) {
            super(response, time);

            parse(3, 0);
        }

        @Override
        public String getDescription() {
            return "Support of ECDH, ECDHC, ECDSA allocation";
        }
    }
}
