package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.ec.EC_Params;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.test.TestSuite;
import cz.crcs.ectester.common.util.ECUtil;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTesterReader;
import cz.crcs.ectester.reader.command.Command;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class CardTestSuite extends TestSuite {
    ECTesterReader.Config cfg;
    CardMngr card;

    CardTestSuite(TestWriter writer, ECTesterReader.Config cfg, CardMngr cardManager, String name, String... description) {
        super(writer, name, description);
        this.card = cardManager;
        this.cfg = cfg;
    }

    public CardMngr getCard() {
        return card;
    }

    public ECTesterReader.Config getCfg() {
        return cfg;
    }

    public Test genOrPreset(EC_Curve curve, Result.ExpectedValue expected) {
        if (cfg.testOptions.contains("preset")) {
            byte[] presetPriv = ECUtil.semiRandomKey(curve);
            EC_Params privParms = new EC_Params(EC_Consts.PARAMETER_S, new byte[][]{presetPriv});
            return CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.CURVE_external, privParms.getParams(), privParms.flatten()), expected);
        } else {
            return CommandTest.expect(new Command.Generate(this.card, ECTesterApplet.KEYPAIR_LOCAL), expected);
        }
    }
}
