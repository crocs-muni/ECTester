package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTesterReader;
import javacard.security.KeyPair;

import java.io.IOException;

import static cz.crcs.ectester.common.test.Result.ExpectedValue;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CardWrongCurvesSuite extends CardTestSuite {

    public CardWrongCurvesSuite(EC_Store dataStore, ECTesterReader.Config cfg) {
        super(dataStore, cfg, "wrong", "The wrong curve suite run whether the card rejects domain parameters which are not curves.");
    }

    @Override
    public void setup(CardMngr cardManager) throws IOException {
        /* Just do the default run on the wrong curves.
         * These should generally fail, the curves aren't curves.
         */
        String desc = "Default run over wrong curve params.";
        if (cfg.primeField) {
            run.addAll(defaultCategoryTests(cardManager, cfg.testSuite, KeyPair.ALG_EC_FP, ExpectedValue.FAILURE, ExpectedValue.FAILURE, ExpectedValue.FAILURE, ExpectedValue.FAILURE, ExpectedValue.FAILURE, desc));
        }
        if (cfg.binaryField) {
            run.addAll(defaultCategoryTests(cardManager, cfg.testSuite, KeyPair.ALG_EC_F2M, ExpectedValue.FAILURE, ExpectedValue.FAILURE, ExpectedValue.FAILURE, ExpectedValue.FAILURE, ExpectedValue.FAILURE, desc));
        }
    }
}
