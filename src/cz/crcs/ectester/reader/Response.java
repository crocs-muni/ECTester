package cz.crcs.ectester.reader;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import javacard.framework.ISO7816;
import javacard.security.KeyPair;

import javax.smartcardio.ResponseAPDU;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class Response {
    protected ResponseAPDU resp;
    protected long time;
    protected short sw1 = 0;
    protected short sw2 = 0;
    protected byte[][] params;
    protected boolean success = true;

    protected Response(ResponseAPDU response, long time) {
        this.resp = response;
        this.time = time;
    }

    protected void parse(int numSW, int numParams) {
        byte[] data = resp.getData();
        int offset = 0;

        //parse SWs in response
        if (--numSW >= 0 && getLength() >= 2) {
            sw1 = Util.getShort(data, offset);
            offset += 2;
            if (sw1 != ISO7816.SW_NO_ERROR)
                success = false;
        }
        if (--numSW >= 0 && getLength() >= 4) {
            sw2 = Util.getShort(data, offset);
            offset += 2;
            if (sw2 != ISO7816.SW_NO_ERROR)
                success = false;
        }

        //try to parse numParams..
        params = new byte[numParams][];
        for (int i = 0; i < numParams; i++) {
            if (data.length - offset < 2) {
                success = false;
                break;
            }
            short paramLength = Util.getShort(data, offset);
            offset += 2;
            if (data.length < offset + paramLength) {
                success = false;
                break;
            }
            params[i] = new byte[paramLength];
            System.arraycopy(data, offset, params[i], 0, paramLength);
            offset += paramLength;
        }
    }

    protected boolean hasParam(int index) {
        return params.length >= index + 1 && params[index] != null;
    }

    protected int getParamLength(int index) {
        return params[index].length;
    }

    protected byte[] getParam(int index) {
        return params[index];
    }

    public ResponseAPDU getAPDU() {
        return resp;
    }

    public long getDuration() {
        return time;
    }

    public int getNaturalSW() {
        return resp.getSW();
    }

    public short getSW1() {
        return sw1;
    }

    public short getSW2() {
        return sw2;
    }

    public int getLength() {
        return resp.getNr();
    }

    public boolean successful() {
        return this.success;
    }

    @Override
    public abstract String toString();


    /**
     *
     */
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
        public String toString() {
            String field = keyClass == KeyPair.ALG_EC_FP ? "ALG_EC_FP" : "ALG_EC_F2M";
            String key;
            if (keyPair == ECTesterApplet.KEYPAIR_BOTH) {
                key = "both keypairs";
            } else {
                key = ((keyPair == ECTesterApplet.KEYPAIR_LOCAL) ? "local" : "remote") + " keypair";
            }
            //TODO general response.toString alignment + 2 SWs
            return String.format("Allocated %s %db %s: %#x", key, keyLength, field, getSW1());
        }
    }

    /**
     *
     */
    public static class Set extends Response {
        private byte keyPair;
        private byte export;
        private byte curve;
        private short params;
        private short corrupted;

        protected Set(ResponseAPDU response, long time, byte keyPair, byte export, byte curve, short params, short corrupted) {
            super(response, time);
            this.keyPair = keyPair;
            this.export = export;
            this.curve = curve;
            this.params = params;
            this.corrupted = corrupted;

            int pairs = 0;
            if ((keyPair & ECTesterApplet.KEYPAIR_LOCAL) != 0) pairs++;
            if ((keyPair & ECTesterApplet.KEYPAIR_REMOTE) != 0) pairs++;
            int exported = 0;
            if ((export & ECTesterApplet.KEYPAIR_LOCAL) != 0) exported++;
            if ((export & ECTesterApplet.KEYPAIR_REMOTE) != 0) exported++;
            int keys = 0;
            if ((export & ECTesterApplet.EXPORT_PUBLIC) != 0) keys++;
            if ((export & ECTesterApplet.EXPORT_PRIVATE) != 0) keys++;
            int paramCount = 0;
            short mask = EC_Consts.PARAMETER_FP;
            while (mask <= EC_Consts.PARAMETER_K) {
                if ((mask & params) != 0) {
                    paramCount++;
                }
                mask = (short) (mask << 1);
            }
            int other = 0;
            if ((export & ECTesterApplet.EXPORT_PUBLIC) != 0 && (params & EC_Consts.PARAMETER_W) != 0) other++;
            if ((export & ECTesterApplet.EXPORT_PRIVATE) != 0 && (params & EC_Consts.PARAMETER_S) != 0) other++;

            parse(pairs, exported * keys * paramCount + exported * other);
        }

        private int getIndex(byte keyPair, short param) {
            byte key = ECTesterApplet.KEYPAIR_LOCAL;
            int index = 0;
            while (key <= ECTesterApplet.KEYPAIR_REMOTE) {
                short mask = EC_Consts.PARAMETER_FP;
                while (mask <= EC_Consts.PARAMETER_S) {
                    if (key == keyPair && param == mask) {
                        return index;
                    }
                    if ((params & mask) != 0 && (key & export) != 0) {
                        if (mask == EC_Consts.PARAMETER_W) {
                            if ((export & ECTesterApplet.EXPORT_PUBLIC) != 0)
                                index++;
                        } else if (mask == EC_Consts.PARAMETER_S) {
                            if ((export & ECTesterApplet.EXPORT_PRIVATE) != 0)
                                index++;
                        } else {
                            index++;
                        }
                    }
                    mask = (short) (mask << 1);
                }

                key = (byte) (key << 1);
            }
            return -1;
        }

        public boolean hasParameter(byte keyPair, short param) {
            return !((export & keyPair) == 0 || (params & param) == 0) && getIndex(keyPair, param) != -1;
        }

        public byte[] getParameter(byte keyPair, short param) {
            return getParam(getIndex(keyPair, param));
        }

        @Override
        public String toString() {
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
            String key;
            if (keyPair == ECTesterApplet.KEYPAIR_BOTH) {
                key = "both keypairs";
            } else {
                key = ((keyPair == ECTesterApplet.KEYPAIR_LOCAL) ? "local" : "remote") + " keypair";
            }
            //TODO general response.toString alignment + 2 SWs
            return String.format("Set %s curve parameters on %s: %#x", name, key, getSW1());
        }

    }

    /**
     *
     */
    public static class Generate extends Response {
        private byte keyPair;
        private byte export;
        private short[] contents;

        protected Generate(ResponseAPDU response, long time, byte keyPair, byte export) {
            super(response, time);
            this.keyPair = keyPair;
            this.export = export;

            int keys = 0;
            if ((export & ECTesterApplet.EXPORT_PUBLIC) != 0) keys++;
            if ((export & ECTesterApplet.EXPORT_PRIVATE) != 0) keys++;
            int pairs = 0;
            if ((export & ECTesterApplet.KEYPAIR_LOCAL) != 0) pairs++;
            if ((export & ECTesterApplet.KEYPAIR_REMOTE) != 0) pairs++;
            int generated = 0;
            if ((keyPair & ECTesterApplet.KEYPAIR_LOCAL) != 0) generated++;
            if ((keyPair & ECTesterApplet.KEYPAIR_REMOTE) != 0) generated++;
            parse(generated, keys * pairs);

            this.contents = new short[4];
            int offset = 0;
            if ((export & ECTesterApplet.KEYPAIR_LOCAL) != 0) {
                if ((export & ECTesterApplet.EXPORT_PUBLIC) != 0) {
                    this.contents[offset] = ECTesterApplet.KEYPAIR_LOCAL | ECTesterApplet.EXPORT_PUBLIC;
                    offset++;
                }
                if ((export & ECTesterApplet.EXPORT_PRIVATE) != 0) {
                    this.contents[offset] = ECTesterApplet.KEYPAIR_LOCAL | ECTesterApplet.EXPORT_PRIVATE;
                    offset++;
                }
            }
            if ((export & ECTesterApplet.KEYPAIR_REMOTE) != 0) {
                if ((export & ECTesterApplet.EXPORT_PUBLIC) != 0) {
                    this.contents[offset] = ECTesterApplet.KEYPAIR_REMOTE | ECTesterApplet.EXPORT_PUBLIC;
                    offset++;
                }
                if ((export & ECTesterApplet.EXPORT_PRIVATE) != 0) {
                    this.contents[offset] = ECTesterApplet.KEYPAIR_REMOTE | ECTesterApplet.EXPORT_PRIVATE;
                    offset++;
                }
            }
        }

        private int getIndex(byte key) {
            for (int i = 0; i < contents.length; i++) {
                if (key == contents[i])
                    return i;
            }
            return -1;
        }

        public boolean hasPublic(byte keyPair) {
            if ((export & ECTesterApplet.EXPORT_PUBLIC) == 0 || (export & keyPair) == 0)
                return false;
            return getIndex((byte) (keyPair | ECTesterApplet.EXPORT_PUBLIC)) != -1;
        }

        public boolean hasPrivate(byte keyPair) {
            if ((export & ECTesterApplet.EXPORT_PRIVATE) == 0 || (export & keyPair) == 0)
                return false;
            return getIndex((byte) (keyPair | ECTesterApplet.EXPORT_PRIVATE)) != -1;
        }

        public byte[] getPublic(byte keyPair) {
            //calculate index and getParam
            int index = getIndex((byte) (keyPair | ECTesterApplet.EXPORT_PUBLIC));
            return getParam(index);
        }

        public byte[] getPrivate(byte keyPair) {
            //calculate index and getParam
            int index = getIndex((byte) (keyPair | ECTesterApplet.EXPORT_PRIVATE));
            return getParam(index);
        }

        @Override
        public String toString() {
            String key;
            if (keyPair == ECTesterApplet.KEYPAIR_BOTH) {
                key = "both keypairs";
            } else {
                key = ((keyPair == ECTesterApplet.KEYPAIR_LOCAL) ? "local" : "remote") + " keypair";
            }
            //TODO general response.toString alignment + 2 SWs
            return String.format("Generated %s: %#x", key, getSW1());
        }

    }

    /**
     *
     */
    public static class ECDH extends Response {
        private byte pubkey;
        private byte privkey;
        private byte export;
        private byte invalid;

        protected ECDH(ResponseAPDU response, long time, byte pubkey, byte privkey, byte export, byte invalid) {
            super(response, time);
            this.pubkey = pubkey;
            this.privkey = privkey;
            this.export = export;
            this.invalid = invalid;

            parse(1, (export & ECTesterApplet.EXPORT_ECDH) != 0 ? 1 : 0);
        }

        public boolean hasSecret() {
            return hasParam(0);
        }

        public byte[] getSecret() {
            return getParam(0);
        }

        @Override
        public String toString() {
            String pub = pubkey == ECTesterApplet.KEYPAIR_LOCAL ? "local" : "remote";
            String priv = privkey == ECTesterApplet.KEYPAIR_LOCAL ? "local" : "remote";
            String validity = invalid != 0 ? "invalid" : "valid";
            //TODO general response.toString alignment + 2SWs
            return String.format("ECDH of %s pubkey and %s privkey(%s point): %#x", pub, priv, validity, getSW1());
        }
    }

    /**
     *
     */
    public static class ECDSA extends Response {
        private byte keyPair;
        private byte export;
        private byte[] raw;

        protected ECDSA(ResponseAPDU response, long time, byte keyPair, byte export, byte[] raw) {
            super(response, time);
            this.keyPair = keyPair;
            this.export = export;
            this.raw = raw;

            parse(1, (export & ECTesterApplet.EXPORT_SIG) != 0 ? 1 : 0);
        }

        public boolean hasSignature() {
            return hasParam(0);
        }

        public byte[] getSignature() {
            return getParam(0);
        }

        @Override
        public String toString() {
            String key = keyPair == ECTesterApplet.KEYPAIR_LOCAL ? "local" : "remote";
            String data = raw == null ? "random" : "provided";
            //TODO general response.toString alignment + 2 SWs
            return String.format("ECDSA with %s keypair(%s data): %#x", key, data, getSW1());
        }

    }
}
