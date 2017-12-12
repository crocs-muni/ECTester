package cz.crcs.ectester.standalone.test;

import cz.crcs.ectester.common.cli.TreeCommandLine;
import cz.crcs.ectester.common.test.TestSuite;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.standalone.ECTesterStandalone;

import java.security.NoSuchAlgorithmException;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class StandaloneTestSuite extends TestSuite {
    TreeCommandLine cli;
    ECTesterStandalone.Config cfg;

    public StandaloneTestSuite(EC_Store dataStore, ECTesterStandalone.Config cfg, TreeCommandLine cli, String name, String description) {
        super(dataStore, name, description);
        this.cfg = cfg;
        this.cli = cli;
    }

    public abstract void setup() throws NoSuchAlgorithmException;
}
