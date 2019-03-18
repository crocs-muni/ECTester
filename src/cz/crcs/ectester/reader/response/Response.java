package cz.crcs.ectester.reader.response;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.util.ByteUtil;
import javacard.framework.ISO7816;

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
    private String description;

    public Response(ResponseAPDU response, String description, long time) {
        this.resp = response;
        this.description = description;
        this.time = time;
    }

    boolean parse(int numSW, int numParams) {
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
        return success;
    }

    public ResponseAPDU getAPDU() {
        return resp;
    }

    public byte[] getData() {
        return resp.getData();
    }

    public long getDuration() {
        return time;
    }

    public short getNaturalSW() {
        return (short) resp.getSW();
    }

    public short[] getSWs() {
        return sws;
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

    public String getDescription() {
        return description;
    }

    /**
     *
     */
    public static class AllocateKeyAgreement extends Response {
        private byte kaType;

        public AllocateKeyAgreement(ResponseAPDU response, String description, long time, byte kaType) {
            super(response, description, time);
            this.kaType = kaType;

            parse(1, 0);
        }
    }

    /**
     *
     */
    public static class AllocateSignature extends Response {
        private byte sigType;

        public AllocateSignature(ResponseAPDU response, String description, long time, byte sigType) {
            super(response, description, time);
            this.sigType = sigType;

            parse(1, 0);
        }
    }

    /**
     *
     */
    public static class Allocate extends Response {
        private byte keyPair;
        private short keyLength;
        private byte keyClass;

        public Allocate(ResponseAPDU response, String description, long time, byte keyPair, short keyLength, byte keyClass) {
            super(response, description, time);
            this.keyPair = keyPair;
            this.keyLength = keyLength;
            this.keyClass = keyClass;

            int pairs = 0;
            if ((keyPair & ECTesterApplet.KEYPAIR_LOCAL) != 0) pairs++;
            if ((keyPair & ECTesterApplet.KEYPAIR_REMOTE) != 0) pairs++;
            parse(pairs, 0);
        }
    }

    /**
     *
     */
    public static class Clear extends Response {
        private byte keyPair;

        public Clear(ResponseAPDU response, String description, long time, byte keyPair) {
            super(response, description, time);
            this.keyPair = keyPair;

            int pairs = 0;
            if ((keyPair & ECTesterApplet.KEYPAIR_LOCAL) != 0) pairs++;
            if ((keyPair & ECTesterApplet.KEYPAIR_REMOTE) != 0) pairs++;
            parse(pairs, 0);
        }
    }

    /**
     *
     */
    public static class Set extends Response {
        private byte keyPair;
        private byte curve;
        private short parameters;

        public Set(ResponseAPDU response, String description, long time, byte keyPair, byte curve, short parameters) {
            super(response, description, time);
            this.keyPair = keyPair;
            this.curve = curve;
            this.parameters = parameters;

            int pairs = 0;
            if ((keyPair & ECTesterApplet.KEYPAIR_LOCAL) != 0) pairs++;
            if ((keyPair & ECTesterApplet.KEYPAIR_REMOTE) != 0) pairs++;

            parse(pairs, 0);
        }
    }

    /**
     *
     */
    public static class Transform extends Response {
        private byte keyPair;
        private byte key;
        private short params;
        private short transformation;

        public Transform(ResponseAPDU response, String description, long time, byte keyPair, byte key, short params, short transformation) {
            super(response, description, time);
            this.keyPair = keyPair;
            this.key = key;
            this.params = params;
            this.transformation = transformation;

            int pairs = 0;
            if ((keyPair & ECTesterApplet.KEYPAIR_LOCAL) != 0) pairs++;
            if ((keyPair & ECTesterApplet.KEYPAIR_REMOTE) != 0) pairs++;

            parse(pairs, 0);
        }
    }

    /**
     *
     */
    public static class Generate extends Response {
        private byte keyPair;

        public Generate(ResponseAPDU response, String description, long time, byte keyPair) {
            super(response, description, time);
            this.keyPair = keyPair;

            int generated = 0;
            if ((keyPair & ECTesterApplet.KEYPAIR_LOCAL) != 0) generated++;
            if ((keyPair & ECTesterApplet.KEYPAIR_REMOTE) != 0) generated++;
            parse(generated, 0);
        }
    }

    /**
     *
     */
    public static class Export extends Response {
        private byte keyPair;
        private byte key;
        private short parameters;

        public Export(ResponseAPDU response, String description, long time, byte keyPair, byte key, short parameters) {
            super(response, description, time);
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
                    if ((parameters & mask) != 0 && (pair & this.keyPair) != 0) {
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
    }

    /**
     *
     */
    public static class ECDH extends Response {
        private byte pubkey;
        private byte privkey;
        private byte export;
        private short transformation;
        private byte type;

        public ECDH(ResponseAPDU response, String description, long time, byte pubkey, byte privkey, byte export, short transformation, byte type) {
            super(response, description, time);
            this.pubkey = pubkey;
            this.privkey = privkey;
            this.export = export;
            this.transformation = transformation;
            this.type = type;

            parse(1, (export == ECTesterApplet.EXPORT_TRUE) ? 1 : 0);
        }

        public short getTransformation() {
            return transformation;
        }

        public byte getType() {
            return type;
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
    }

    /**
     *
     */
    public static class ECDSA extends Response {
        private byte keyPair;
        private byte sigType;
        private byte export;
        private byte[] raw;

        public ECDSA(ResponseAPDU response, String description, long time, byte keyPair, byte sigType, byte export, byte[] raw) {
            super(response, description, time);
            this.keyPair = keyPair;
            this.sigType = sigType;
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
    }

    /**
     *
     */
    public static class Cleanup extends Response {

        public Cleanup(ResponseAPDU response, String description, long time) {
            super(response, description, time);

            parse(1, 0);
        }
    }

    /**
     *
     */
    public static class GetInfo extends Response {
        private short base;
        private short jcVersion;
        private short cleanupSupport;
        private short apduBufferLength;
        private short ramArrayLength;
        private short ramArray2Length;
        private short apduArrayLength;

        public GetInfo(ResponseAPDU response, String description, long time) {
            super(response, description, time);

            parse(1, 1);
            int offset = 2 + 2 + getParamLength(0);
            byte[] data = getData();
            base = ByteUtil.getShort(data, offset);
            offset += 2;
            jcVersion = ByteUtil.getShort(data, offset);
            offset += 2;
            cleanupSupport = ByteUtil.getShort(data, offset);
            offset += 2;
            apduBufferLength = ByteUtil.getShort(data, offset);
            offset += 2;
            ramArrayLength = ByteUtil.getShort(data, offset);
            offset += 2;
            ramArray2Length = ByteUtil.getShort(data, offset);
            offset += 2;
            apduArrayLength = ByteUtil.getShort(data, offset);
        }

        public String getVersion() {
            return new String(getParam(0));
        }

        public short getBase() {
            return base;
        }

        public float getJavaCardVersion() {
            byte major = (byte) (jcVersion >> 8);
            byte minor = (byte) (jcVersion & 0xff);
            int minorSize;
            if (minor == 0) {
                minorSize = 1;
            } else {
                minorSize = (int) Math.ceil(Math.log10(minor));
            }
            return (major + ((float) (minor) / (minorSize * 10)));
        }

        public boolean getCleanupSupport() {
            return cleanupSupport == 1;
        }

        public short getApduBufferLength() {
            return apduBufferLength;
        }

        public short getRamArrayLength() {
            return ramArrayLength;
        }

        public short getRamArray2Length() {
            return ramArray2Length;
        }

        public short getApduArrayLength() {
            return apduArrayLength;
        }
    }

    /**
     *
     */
    public static class SetDryRunMode extends Response {

        public SetDryRunMode(ResponseAPDU response, String description, long time) {
            super(response, description, time);

            parse(1, 0);
        }
    }
}
