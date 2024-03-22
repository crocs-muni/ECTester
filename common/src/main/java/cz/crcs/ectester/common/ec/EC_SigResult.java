package cz.crcs.ectester.common.ec;

import cz.crcs.ectester.common.util.CardUtil;

/**
 * A result of EC based Signature operation.
 *
 * @author Jan Jancar johny@neuromancer.sk
 */
public class EC_SigResult extends EC_Data {
    private String sig;
    private String curve;
    private String signKey;
    private String verifyKey;

    private String data;
    private String desc;

    public EC_SigResult(String sig, String curve, String signKey, String verifyKey, String raw) {
        super(1);
        this.sig = sig;
        this.curve = curve;
        this.signKey = signKey;
        this.verifyKey = verifyKey;
        this.data = raw;
    }

    public EC_SigResult(String id, String sig, String curve, String signKey, String verifyKey, String data) {
        this(sig, curve, signKey, verifyKey, data);
        this.id = id;
    }

    public EC_SigResult(String id, String sig, String curve, String signKey, String verifyKey, String data, String desc) {
        this(id, sig, curve, signKey, verifyKey, data);
        this.desc = desc;
    }

    public String getSig() {
        return sig;
    }

    public byte getJavaCardSig() {
        return CardUtil.getSig(sig);
    }

    public String getCurve() {
        return curve;
    }

    public String getSignKey() {
        return signKey;
    }

    public String getVerifyKey() {
        return verifyKey;
    }

    public byte[] getSigData() {
        if (data == null) {
            return null;
        } else {
            return parse(data);
        }
    }

    public String getDesc() {
        return desc;
    }

    @Override
    public String toString() {
        return "<" + getId() + "> " + sig + " result over " + curve + ", " + signKey + " + " + verifyKey + (data == null ? "" : " of data \"" + data + "\"") + (desc == null ? "" : ": " + desc) + System.lineSeparator() + super.toString();
    }

}
