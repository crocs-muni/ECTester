package cz.crcs.ectester.common.ec;

import cz.crcs.ectester.common.util.CardUtil;

/**
 * A result of EC based Key agreement operation.
 *
 * @author Jan Jancar johny@neuromancer.sk
 */
public class EC_KAResult extends EC_Data {
    private String ka;
    private String curve;
    private String oneKey;
    private String otherKey;

    private String desc;

    public EC_KAResult(String ka, String curve, String oneKey, String otherKey) {
        super(1);
        this.ka = ka;
        this.curve = curve;
        this.oneKey = oneKey;
        this.otherKey = otherKey;
    }

    public EC_KAResult(String id, String ka, String curve, String oneKey, String otherKey) {
        this(ka, curve, oneKey, otherKey);
        this.id = id;
    }

    public EC_KAResult(String id, String ka, String curve, String oneKey, String otherKey, String desc) {
        this(id, ka, curve, oneKey, otherKey);
        this.desc = desc;
    }

    public String getKA() {
        return ka;
    }

    public byte getJavaCardKA() {
        return CardUtil.getKA(ka);
    }

    public String getCurve() {
        return curve;
    }

    public String getOneKey() {
        return oneKey;
    }

    public String getOtherKey() {
        return otherKey;
    }

    public String getDesc() {
        return desc;
    }

    @Override
    public String toString() {
        return "<" + getId() + "> " + ka + " result over " + curve + ", " + oneKey + " + " + otherKey + (desc == null ? "" : ": " + desc) + System.lineSeparator() + super.toString();
    }

}
