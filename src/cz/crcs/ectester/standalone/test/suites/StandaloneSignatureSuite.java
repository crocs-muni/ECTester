package cz.crcs.ectester.standalone.test.suites;

import cz.crcs.ectester.common.cli.TreeCommandLine;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.standalone.ECTesterStandalone;

public class StandaloneSignatureSuite extends StandaloneTestSuite {
    public StandaloneSignatureSuite(TestWriter writer, ECTesterStandalone.Config cfg, TreeCommandLine cli) {
        super(writer, cfg, cli, "signature", "The signature test suite tests verifying various malformed and well-formed but invalid signatures.",
                "Supports options:",
                "\t - gt/kpg-type",
                "\t - st/sig-type (select multiple types by separating them with commas)");
    }

    @Override
    protected void runTests() throws Exception {

    }
}
