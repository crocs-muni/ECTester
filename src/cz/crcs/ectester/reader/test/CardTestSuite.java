package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.TestSuite;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTesterReader;

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
}
