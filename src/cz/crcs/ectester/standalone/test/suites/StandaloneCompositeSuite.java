package cz.crcs.ectester.standalone.test.suites;

import cz.crcs.ectester.common.cli.TreeCommandLine;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.standalone.ECTesterStandalone;

public class StandaloneCompositeSuite extends StandaloneTestSuite {
    public StandaloneCompositeSuite(TestWriter writer, ECTesterStandalone.Config cfg, TreeCommandLine cli) {
        super(writer, cfg, cli, "composite", "The composite suite runs ECDH over curves with composite order.",
                "Various types of compositeness is tested: smooth numbers, Carmichael pseudo-prime, prime square, product of two large primes.");
    }

    @Override
    protected void runTests() throws Exception {

    }
}
