package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.ec.EC_Params;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.test.TestSuite;
import cz.crcs.ectester.common.util.ECUtil;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTesterReader;
import cz.crcs.ectester.reader.command.Command;

import java.util.Arrays;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class CardTestSuite extends TestSuite {
    ECTesterReader.Config cfg;
    CardMngr card;
    String[] options;

    CardTestSuite(TestWriter writer, ECTesterReader.Config cfg, CardMngr cardManager, String name, String[] options, String... description) {
        super(writer, name, description);
        this.card = cardManager;
        this.cfg = cfg;
        this.options = options;
    }

    public CardMngr getCard() {
        return card;
    }

    public ECTesterReader.Config getCfg() {
        return cfg;
    }

    public String[] getOptions() {
        if (options != null) {
            return options.clone();
        } else {
            return options;
        }
    }

    public Test setupKeypairs(EC_Curve curve, Result.ExpectedValue expected, byte keyPair) {
        if ((Arrays.asList(options).contains("preset") && cfg.testOptions.contains("preset")) || (Arrays.asList(options).contains("random") && cfg.testOptions.contains("random"))) {
            Test setLocal = null;
            if ((keyPair & ECTesterApplet.KEYPAIR_LOCAL) != 0) {
                EC_Params priv;
                if (cfg.testOptions.contains("preset")) {
                    priv = ECUtil.fixedRandomKey(curve);
                } else {
                    priv = ECUtil.fullRandomKey(curve);
                }
                setLocal = CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.CURVE_external, priv.getParams(), priv.flatten()), expected);
            }
            Test setRemote = null;
            if ((keyPair & ECTesterApplet.KEYPAIR_REMOTE) != 0) {
                EC_Params pub;
                if (cfg.testOptions.contains("preset")) {
                    pub = ECUtil.fixedRandomPoint(curve);
                } else {
                    pub = ECUtil.fullRandomPoint(curve);
                }
                if (pub == null) {
                    setRemote = CommandTest.expect(new Command.Generate(this.card, ECTesterApplet.KEYPAIR_REMOTE), expected);
                } else {
                    setRemote = CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, pub.getParams(), pub.flatten()), expected);
                }
            }

            if (keyPair == ECTesterApplet.KEYPAIR_LOCAL) {
                return setLocal;
            } else if (keyPair == ECTesterApplet.KEYPAIR_REMOTE) {
                return setRemote;
            } else {
                String desc;
                if (cfg.testOptions.contains("preset")) {
                    desc = "Set semi-random parameters.";
                } else {
                    desc = "Set fully-random parameters.";
                }
                return CompoundTest.all(expected, desc, setLocal, setRemote);
            }
        } else {
            return CommandTest.expect(new Command.Generate(this.card, keyPair), expected);
        }
    }
}
