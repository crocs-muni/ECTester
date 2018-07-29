package cz.crcs.ectester.common.ec;

import cz.crcs.ectester.applet.EC_Consts;

/**
 * An EC keypair, contains both the W and S parameters.
 *
 * @author Jan Jancar johny@neuromancer.sk
 */
public class EC_Keypair extends EC_Params {
    private String curve;
    private String desc;

    public EC_Keypair(String curve) {
        super(EC_Consts.PARAMETERS_KEYPAIR);
        this.curve = curve;
    }

    public EC_Keypair(String curve, String desc) {
        this(curve);
        this.desc = desc;
    }

    public EC_Keypair(String id, String curve, String desc) {
        this(curve, desc);
        this.id = id;
    }

    public String getCurve() {
        return curve;
    }

    public String getDesc() {
        return desc;
    }

    @Override
    public String toString() {
        return "<" + getId() + "> EC Keypair, over " + curve + (desc == null ? "" : ": " + desc) + System.lineSeparator() + super.toString();
    }
}
