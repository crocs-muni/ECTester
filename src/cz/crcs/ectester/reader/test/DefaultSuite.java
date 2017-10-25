package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTester;
import cz.crcs.ectester.reader.command.Command;
import javacard.security.KeyPair;

import java.io.IOException;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class DefaultSuite extends TestSuite {

    public DefaultSuite(EC_Store dataStore, ECTester.Config cfg) {
        super(dataStore, cfg, "default", "The default test suite tests basic support of ECDH and ECDSA.");
    }

    @Override
    public void setup(CardMngr cardManager) throws IOException {
        tests.add(new Test.Simple(new Command.Support(cardManager), Result.Value.ANY));
        if (cfg.namedCurve != null) {
            if (cfg.primeField) {
                tests.addAll(defaultCategoryTests(cardManager, cfg.namedCurve, KeyPair.ALG_EC_FP, Result.Value.SUCCESS, Result.Value.SUCCESS, Result.Value.SUCCESS, Result.Value.SUCCESS));
            }
            if (cfg.binaryField) {
                tests.addAll(defaultCategoryTests(cardManager, cfg.namedCurve, KeyPair.ALG_EC_F2M, Result.Value.SUCCESS, Result.Value.SUCCESS, Result.Value.SUCCESS, Result.Value.SUCCESS));
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
        tests.add(new Test.Simple(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_BOTH, keyLength, keyType), Result.Value.SUCCESS));
        Command curve = Command.prepareCurve(cardManager, dataStore, cfg, ECTesterApplet.KEYPAIR_BOTH, keyLength, keyType);
        if (curve != null)
            tests.add(new Test.Simple(curve, Result.Value.SUCCESS));
        tests.addAll(defaultCurveTests(cardManager, Result.Value.SUCCESS, Result.Value.SUCCESS, Result.Value.SUCCESS));
        tests.add(new Test.Simple(new Command.Cleanup(cardManager), Result.Value.ANY));
    }
}
