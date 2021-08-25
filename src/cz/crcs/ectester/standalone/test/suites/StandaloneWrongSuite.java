package cz.crcs.ectester.standalone.test.suites;

import cz.crcs.ectester.common.cli.TreeCommandLine;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.standalone.ECTesterStandalone;

public class StandaloneWrongSuite extends StandaloneTestSuite {
    public StandaloneWrongSuite(TestWriter writer, ECTesterStandalone.Config cfg, TreeCommandLine cli) {
        super(writer, cfg, cli, "composite", "The wrong curve suite tests whether the library rejects domain parameters which are not curves.");
    }


    @Override
    protected void runTests() throws Exception {

    }
}
