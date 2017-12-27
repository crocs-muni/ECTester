package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.test.BaseRunnable;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTesterReader;
import cz.crcs.ectester.reader.command.Command;
import javacard.security.KeyPair;

import java.io.IOException;

import static cz.crcs.ectester.common.test.Result.ExpectedValue;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CardDefaultSuite extends CardTestSuite {

    public CardDefaultSuite(EC_Store dataStore, ECTesterReader.Config cfg) {
        super(dataStore, cfg, "default", "The default test suite run basic support of ECDH and ECDSA.");
    }

    @Override
    public void setup(CardMngr cardManager) throws IOException {
        //run.add(CommandTest.expect(new Command.Support(cardManager), ExpectedValue.ANY));
        if (cfg.namedCurve != null) {
            String desc = "Default run over the " + cfg.namedCurve + " curve category.";
            if (cfg.primeField) {
                run.addAll(defaultCategoryTests(cardManager, cfg.namedCurve, KeyPair.ALG_EC_FP, ExpectedValue.SUCCESS, ExpectedValue.SUCCESS, ExpectedValue.SUCCESS, ExpectedValue.ANY, ExpectedValue.SUCCESS, desc));
            }
            if (cfg.binaryField) {
                run.addAll(defaultCategoryTests(cardManager, cfg.namedCurve, KeyPair.ALG_EC_F2M, ExpectedValue.SUCCESS, ExpectedValue.SUCCESS, ExpectedValue.SUCCESS, ExpectedValue.ANY, ExpectedValue.SUCCESS, desc));
            }
        } else {
            if (cfg.all) {
                if (cfg.primeField) {
                    //iterate over prime curve sizes used: EC_Consts.FP_SIZES
                    for (short keyLength : EC_Consts.FP_SIZES) {
                        defaultTests(cardManager, keyLength, KeyPair.ALG_EC_FP);
                    }
                }
                if (cfg.binaryField) {
                    //iterate over binary curve sizes used: EC_Consts.F2M_SIZES
                    for (short keyLength : EC_Consts.F2M_SIZES) {
                        defaultTests(cardManager, keyLength, KeyPair.ALG_EC_F2M);
                    }
                }
            } else {
                if (cfg.primeField) {
                    defaultTests(cardManager, (short) cfg.bits, KeyPair.ALG_EC_FP);
                }

                if (cfg.binaryField) {
                    defaultTests(cardManager, (short) cfg.bits, KeyPair.ALG_EC_F2M);
                }
            }
        }
    }

    private void defaultTests(CardMngr cardManager, short keyLength, byte keyType) throws IOException {
        run.add(CommandTest.expect(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_BOTH, keyLength, keyType), ExpectedValue.SUCCESS));
        Command curve = Command.prepareCurve(cardManager, dataStore, cfg, ECTesterApplet.KEYPAIR_BOTH, keyLength, keyType);
        if (curve != null)
            run.add(CommandTest.expect(curve, ExpectedValue.SUCCESS));
        run.add(defaultCurveTests(cardManager, ExpectedValue.SUCCESS, ExpectedValue.SUCCESS, ExpectedValue.ANY, ExpectedValue.SUCCESS, "Default run."));
        run.add(new BaseRunnable(() -> new Command.Cleanup(cardManager)));
    }
}
