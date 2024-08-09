package cz.crcs.ectester.standalone.test.suites;

import cz.crcs.ectester.common.cli.TreeCommandLine;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.standalone.ECTesterStandalone;

/**
 * @author David Hofman
 */
public class StandaloneDegenerateSuite extends StandaloneForeignSuite {
    public StandaloneDegenerateSuite(TestWriter writer, ECTesterStandalone.Config cfg, TreeCommandLine cli) {
        super(writer, cfg, cli, "degenerate", "The degenerate suite tests whether the library rejects points outside of the curve during ECDH.",
                "The tested points lie on a part of the plane for which some Edwards, Hessian and Huff form addition formulas degenerate into exponentiation in the base finite field.",
                "Supports options:", "\t - gt/kpg-type", "\t - kt/ka-type (select multiple types by separating them with commas)");
    }
}
