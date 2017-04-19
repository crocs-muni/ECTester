package cz.crcs.ectester.reader.ec;

import cz.crcs.ectester.applet.EC_Consts;
import javacard.security.KeyPair;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class EC_Curve extends EC_Params {
    private short bits;
    private byte field;
    private String desc;

    /**
     * @param bits
     * @param field KeyPair.ALG_EC_FP or KeyPair.ALG_EC_F2M
     */
    public EC_Curve(short bits, byte field) {
        super(field == KeyPair.ALG_EC_FP ? EC_Consts.PARAMETERS_DOMAIN_FP : EC_Consts.PARAMETERS_DOMAIN_F2M);
        this.bits = bits;
        this.field = field;
    }

    public EC_Curve(String id, short bits, byte field) {
        this(bits, field);
        this.id = id;
    }

    public EC_Curve(String id, short bits, byte field, String desc) {
        this(id, bits, field);
        this.desc = desc;
    }

    public short getBits() {
        return bits;
    }

    public byte getField() {
        return field;
    }

    public String getDesc() {
        return desc;
    }

    @Override
    public String toString() {
        return "<" + getId() + "> " + (field == KeyPair.ALG_EC_FP ? "Prime" : "Binary") + " field Elliptic curve (" + String.valueOf(bits) + "b)" + (desc == null ? "" : ": " + desc);
    }
}
