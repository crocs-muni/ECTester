package cz.crcs.ectester.standalone.test.suites;

import cz.crcs.ectester.common.cli.TreeCommandLine;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.standalone.ECTesterStandalone;

public class StandaloneTestVectorSuite extends StandaloneTestSuite {

    public StandaloneTestVectorSuite(TestWriter writer, ECTesterStandalone.Config cfg, TreeCommandLine cli) {
        super(writer, cfg, cli, "test-vectors", "The test-vectors suite contains a collection of test vectors which test basic ECDH correctness.");
    }

    @Override
    protected void runTests() throws Exception {
        System.out.println("<test output goes here>");
    }
}
