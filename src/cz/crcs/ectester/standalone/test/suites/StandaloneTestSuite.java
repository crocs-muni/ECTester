package cz.crcs.ectester.standalone.test.suites;

import cz.crcs.ectester.common.cli.TreeCommandLine;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.TestSuite;
import cz.crcs.ectester.standalone.ECTesterStandalone;
import cz.crcs.ectester.standalone.libs.ProviderECLibrary;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class StandaloneTestSuite extends TestSuite {
    TreeCommandLine cli;
    ECTesterStandalone.Config cfg;

    public StandaloneTestSuite(TestWriter writer, ECTesterStandalone.Config cfg, TreeCommandLine cli, String name, String... description) {
        super(writer, name, description);
        this.cfg = cfg;
        this.cli = cli;
    }

    public ProviderECLibrary getLibrary() {
        return cfg.selected;
    }
}
