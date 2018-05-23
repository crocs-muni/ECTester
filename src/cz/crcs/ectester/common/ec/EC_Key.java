package cz.crcs.ectester.common.ec;

import cz.crcs.ectester.applet.EC_Consts;

/**
 * An abstract-like EC key. Concrete implementations create a public and private keys.
 *
 * @author Jan Jancar johny@neuromancer.sk
 */
public class EC_Key extends EC_Params {

    private String curve;
    private String desc;

    private EC_Key(short mask, String curve) {
        super(mask);
        this.curve = curve;
    }

    private EC_Key(short mask, String curve, String desc) {
        this(mask, curve);
        this.desc = desc;
    }

    private EC_Key(String id, short mask, String curve, String desc) {
        this(mask, curve, desc);
        this.id = id;
    }

    public String getCurve() {
        return curve;
    }

    public String getDesc() {
        return desc;
    }

    /**
     * An EC public key, contains the W parameter.
     */
    public static class Public extends EC_Key {

        public Public(String curve) {
            super(EC_Consts.PARAMETER_W, curve);
        }

        public Public(String curve, String desc) {
            super(EC_Consts.PARAMETER_W, curve, desc);
        }

        public Public(String id, String curve, String desc) {
            super(id, EC_Consts.PARAMETER_W, curve, desc);
        }

        @Override
        public String toString() {
            return "<" + getId() + "> EC Public key, over " + getCurve() + (getDesc() == null ? "" : ": " + getDesc()) + System.lineSeparator() + super.toString();
        }
    }

    /**
     * An EC private key, contains the S parameter.
     */
    public static class Private extends EC_Key {

        public Private(String curve) {
            super(EC_Consts.PARAMETER_S, curve);
        }

        public Private(String curve, String desc) {
            super(EC_Consts.PARAMETER_S, curve, desc);
        }

        public Private(String id, String curve, String desc) {
            super(id, EC_Consts.PARAMETER_S, curve, desc);
        }

        @Override
        public String toString() {
            return "<" + getId() + "> EC Private key, over " + getCurve() + (getDesc() == null ? "" : ": " + getDesc()) + System.lineSeparator() + super.toString();
        }
    }
}
