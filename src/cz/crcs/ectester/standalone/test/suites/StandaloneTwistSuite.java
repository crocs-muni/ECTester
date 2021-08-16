package cz.crcs.ectester.standalone.test.suites;

import cz.crcs.ectester.common.cli.TreeCommandLine;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.standalone.ECTesterStandalone;

public class StandaloneTwistSuite extends StandaloneTestSuite {
    public StandaloneTwistSuite(TestWriter writer, ECTesterStandalone.Config cfg, TreeCommandLine cli) {
        super(writer, cfg, cli, "twist", "The twist test suite tests whether the library correctly rejects points on the quadratic twist of the curve during ECDH.", "Supports options:", "\t - kt/ka-type (select multiple types by separating them with commas)");
    }

    @Override
    protected void runTests() throws Exception {
        System.out.println("Not implemented.");
    }
}
