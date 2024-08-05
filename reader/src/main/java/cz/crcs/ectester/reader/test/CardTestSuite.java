package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.common.ec.EC_Consts;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.ec.EC_Params;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.test.TestSuite;
import cz.crcs.ectester.common.util.CardConsts;
import cz.crcs.ectester.common.util.ECUtil;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTesterReader;
import cz.crcs.ectester.reader.command.Command;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

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

    protected Test setupKeypairs(EC_Curve curve, Result.ExpectedValue expected, byte keyPair) {
        if (cfg.testKeySetup.equals("deterministic") || cfg.testKeySetup.equals("random")) {
            Test setLocal = null;
            if ((keyPair & CardConsts.KEYPAIR_LOCAL) != 0) {
                EC_Params priv = preparePrivkey(curve);
                setLocal = CommandTest.expect(new Command.Set(this.card, CardConsts.KEYPAIR_LOCAL, EC_Consts.CURVE_external, priv.getParams(), priv.flatten()), expected);
            }
            Test setRemote = null;
            if ((keyPair & CardConsts.KEYPAIR_REMOTE) != 0) {
                EC_Params pub = preparePubkey(curve);
                if (pub == null) {
                    setRemote = CommandTest.expect(new Command.Generate(this.card, CardConsts.KEYPAIR_REMOTE), expected);
                } else {
                    setRemote = CommandTest.expect(new Command.Set(this.card, CardConsts.KEYPAIR_REMOTE, EC_Consts.CURVE_external, pub.getParams(), pub.flatten()), expected);
                }
            }

            if (keyPair == CardConsts.KEYPAIR_LOCAL) {
                return setLocal;
            } else if (keyPair == CardConsts.KEYPAIR_REMOTE) {
                return setRemote;
            } else {
                String desc;
                if (cfg.testKeySetup.equals("deterministic")) {
                    desc = "Set deterministic parameters.";
                } else {
                    desc = "Set fully-random parameters.";
                }
                return CompoundTest.all(Result.ExpectedValue.SUCCESS, desc, setLocal, setRemote);
            }
        } else {
            return CommandTest.expect(new Command.Generate(this.card, keyPair), expected);
        }
    }

    protected EC_Params preparePrivkey(EC_Curve curve) {
        if (cfg.testKeySetup.equals("deterministic")) {
            return ECUtil.fixedRandomKey(curve);
        } else {
            return ECUtil.fullRandomKey(curve);
        }
    }

    protected EC_Params preparePubkey(EC_Curve curve) {
        if (cfg.testKeySetup.equals("deterministic")) {
            return ECUtil.fixedRandomPoint(curve);
        } else {
            return ECUtil.fullRandomPoint(curve);
        }
    }

    protected SecureRandom setupRandom(EC_Curve curve) {
        if (cfg.testDataSetup.equals("random")) {
            return new SecureRandom();
        } else {
            return new SecureRandom(ECUtil.hashCurve(curve));
        }
    }

    protected SecureRandom setupRandom(int seed) {
        if (cfg.testDataSetup.equals("random")) {
            return new SecureRandom();
        } else {
            ByteBuffer b = ByteBuffer.allocate(4);
            b.putInt(seed);
            return new SecureRandom(b.array());
        }
    }
}
