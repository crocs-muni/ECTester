package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.util.CardUtil;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTesterReader;
import cz.crcs.ectester.reader.command.Command;

import java.util.Map;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CardMiscSuite extends CardTestSuite {

    public CardMiscSuite(TestWriter writer, ECTesterReader.Config cfg, CardMngr cardManager) {
        super(writer, cfg, cardManager, "miscellaneous", "Some miscellaneous tests, tries ECDH and ECDSA over supersingular curves, anomalous curves and some Barreto-Naehrig curves with small embedding degree and CM discriminant.");
    }

    @Override
    protected void runTests() throws Exception {
        Map<String, EC_Curve> anCurves = EC_Store.getInstance().getObjects(EC_Curve.class, "anomalous");
        Map<String, EC_Curve> ssCurves = EC_Store.getInstance().getObjects(EC_Curve.class, "supersingular");
        Map<String, EC_Curve> bnCurves = EC_Store.getInstance().getObjects(EC_Curve.class, "Barreto-Naehrig");

        testCurves(anCurves, "anomalous", Result.ExpectedValue.FAILURE);
        testCurves(ssCurves, "supersingular", Result.ExpectedValue.FAILURE);
        testCurves(bnCurves, "Barreto-Naehrig", Result.ExpectedValue.ANY);
    }

    private void testCurves(Map<String, EC_Curve> curves, String catName, Result.ExpectedValue expected) throws Exception {
        for (EC_Curve curve : curves.values()) {
            Test allocateFirst = runTest(CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), curve.getField()), Result.ExpectedValue.SUCCESS));
            if (!allocateFirst.ok()) {
                doTest(CompoundTest.all(Result.ExpectedValue.FAILURE, "No support for " + curve.getBits() + "b " + CardUtil.getKeyTypeString(curve.getField()) + ".", allocateFirst));
                continue;
            }

            Test set = CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), Result.ExpectedValue.SUCCESS);
            Test generate = CommandTest.expect(new Command.Generate(this.card, ECTesterApplet.KEYPAIR_BOTH), Result.ExpectedValue.ANY);
            Test ka = CommandTest.expect(new Command.ECDH(this.card, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.TRANSFORMATION_NONE, EC_Consts.KeyAgreement_ALG_EC_SVDP_DH), expected);
            Test sig = CommandTest.expect(new Command.ECDSA(this.card, ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.Signature_ALG_ECDSA_SHA, ECTesterApplet.EXPORT_FALSE, null), expected);
            Test perform = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Perform ECDH and ECDSA", ka, sig);

            if (cfg.cleanup) {
                Test cleanup = CommandTest.expect(new Command.Cleanup(this.card), Result.ExpectedValue.ANY);
                doTest(CompoundTest.greedyAll(Result.ExpectedValue.SUCCESS, "Tests over " + curve.getBits() + " " + catName + " curve: " + curve.getId() + ".", allocateFirst, set, generate, perform, cleanup));
            } else {
                doTest(CompoundTest.greedyAll(Result.ExpectedValue.SUCCESS, "Tests over " + curve.getBits() + " " + catName + " curve: " + curve.getId() + ".", allocateFirst, set, generate, perform));
            }
        }
    }
}
