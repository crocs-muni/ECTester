package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTester;
import cz.crcs.ectester.reader.output.TestWriter;
import javacard.security.KeyPair;

import javax.smartcardio.CardException;
import java.io.IOException;
import java.util.List;

/**
 *
 * @author Jan Jancar johny@neuromancer.sk
 */
public class WrongCurvesSuite extends TestSuite {

    public WrongCurvesSuite(EC_Store dataStore, ECTester.Config cfg) {
        super(dataStore, cfg, "wrong", "");
    }

    @Override
    public void setup(CardMngr cardManager) throws IOException {
        /* Just do the default tests on the wrong curves.
         * These should generally fail, the curves aren't curves.
         */
        if (cfg.primeField) {
            tests.addAll(defaultCategoryTests(cardManager, cfg.testSuite, KeyPair.ALG_EC_FP, Result.Value.FAILURE, Result.Value.FAILURE, Result.Value.FAILURE, Result.Value.FAILURE));
        }
        if (cfg.binaryField) {
            tests.addAll(defaultCategoryTests(cardManager, cfg.testSuite, KeyPair.ALG_EC_F2M, Result.Value.FAILURE, Result.Value.FAILURE, Result.Value.FAILURE, Result.Value.FAILURE));
        }
    }
}
