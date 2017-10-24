package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTester;
import cz.crcs.ectester.reader.output.OutputWriter;
import javacard.security.KeyPair;

import javax.smartcardio.CardException;
import java.io.IOException;
import java.util.List;

/**
 *
 * @author Jan Jancar johny@neuromancer.sk
 */
public class WrongCurvesSuite extends TestSuite {

    public WrongCurvesSuite(EC_Store dataStore, ECTester.Config cfg, OutputWriter writer) {
        super(dataStore, cfg, writer, "wrong");
    }

    @Override
    public List<Test> run(CardMngr cardManager) throws CardException, IOException {
        /* Just do the default tests on the wrong curves.
         * These should generally fail, the curves aren't curves.
         */
        if (cfg.primeField) {
            tests.addAll(defaultCategoryTests(cardManager, cfg.testSuite, KeyPair.ALG_EC_FP, Test.Result.FAILURE, Test.Result.FAILURE, Test.Result.FAILURE, Test.Result.FAILURE));
        }
        if (cfg.binaryField) {
            tests.addAll(defaultCategoryTests(cardManager, cfg.testSuite, KeyPair.ALG_EC_F2M, Test.Result.FAILURE, Test.Result.FAILURE, Test.Result.FAILURE, Test.Result.FAILURE));
        }
        return super.run(cardManager);
    }
}
