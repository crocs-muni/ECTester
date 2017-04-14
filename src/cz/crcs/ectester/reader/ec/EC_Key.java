package cz.crcs.ectester.reader.ec;

import cz.crcs.ectester.applet.EC_Consts;

/**
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

    public String getCurve() {
        return curve;
    }

    public String getDesc() {
        return desc;
    }

    public static class Public extends EC_Key {

        public Public(String curve) {
            super(EC_Consts.PARAMETER_W, curve);
        }

        public Public(String curve, String desc) {
            super(EC_Consts.PARAMETER_W, curve, desc);
        }

        @Override
        public String toString() {
            return "EC Public key, over " + getCurve() + (getDesc() == null ? "" : ": " + getDesc());
        }
    }

    public static class Private extends EC_Key {

        public Private(String curve) {
            super(EC_Consts.PARAMETER_S, curve);
        }

        public Private(String curve, String desc) {
            super(EC_Consts.PARAMETER_S, curve, desc);
        }

        @Override
        public String toString() {
            return "EC Private key, over " + getCurve() + (getDesc() == null ? "" : ": " + getDesc());
        }
    }
}
