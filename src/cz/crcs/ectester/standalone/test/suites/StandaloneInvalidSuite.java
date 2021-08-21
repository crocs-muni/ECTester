package cz.crcs.ectester.standalone.test.suites;

import cz.crcs.ectester.common.cli.TreeCommandLine;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.standalone.ECTesterStandalone;

public class StandaloneInvalidSuite extends StandaloneTestSuite {
    public StandaloneInvalidSuite(TestWriter writer, ECTesterStandalone.Config cfg, TreeCommandLine cli) {
        super(writer, cfg, cli, "invalid", "The invalid curve suite tests whether the card rejects points outside of the curve during ECDH.", "Supports options:", "\t - gt/kpg-type", "\t - kt/ka-type (select multiple types by separating them with commas)");
    }

    @Override
    protected void runTests() throws Exception {

    }
}
