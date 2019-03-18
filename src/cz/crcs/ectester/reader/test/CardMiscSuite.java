package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTesterReader;
import cz.crcs.ectester.reader.command.Command;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CardMiscSuite extends CardTestSuite {

    public CardMiscSuite(TestWriter writer, ECTesterReader.Config cfg, CardMngr cardManager) {
        super(writer, cfg, cardManager, "miscellaneous", new String[]{"preset", "random"}, "Some miscellaneous tests, tries ECDH and ECDSA over supersingular curves, anomalous curves,",
                "Barreto-Naehrig curves with small embedding degree and CM discriminant, MNT curves,",
                "some Montgomery curves transformed to short Weierstrass form and Curve25519 transformed to short Weierstrass form.");
    }

    @Override
    protected void runTests() throws Exception {
        Map<String, EC_Curve> anCurves = EC_Store.getInstance().getObjects(EC_Curve.class, "anomalous");
        Map<String, EC_Curve> ssCurves = EC_Store.getInstance().getObjects(EC_Curve.class, "supersingular");
        Map<String, EC_Curve> bnCurves = EC_Store.getInstance().getObjects(EC_Curve.class, "Barreto-Naehrig");
        Map<String, EC_Curve> mntCurves = EC_Store.getInstance().getObjects(EC_Curve.class, "MNT");
        List<EC_Curve> mCurves = new ArrayList<>();
        mCurves.add(EC_Store.getInstance().getObject(EC_Curve.class, "other", "M-221"));
        mCurves.add(EC_Store.getInstance().getObject(EC_Curve.class, "other", "M-383"));
        mCurves.add(EC_Store.getInstance().getObject(EC_Curve.class, "other", "M-511"));
        EC_Curve curve25519 = EC_Store.getInstance().getObject(EC_Curve.class, "other", "Curve25519");

        testCurves(anCurves.values(), "anomalous", Result.ExpectedValue.FAILURE);
        testCurves(ssCurves.values(), "supersingular", Result.ExpectedValue.FAILURE);
        testCurves(bnCurves.values(), "Barreto-Naehrig", Result.ExpectedValue.SUCCESS);
        testCurves(mntCurves.values(), "MNT", Result.ExpectedValue.SUCCESS);
        testCurves(mCurves, "Montgomery", Result.ExpectedValue.SUCCESS);
        testCurve(curve25519, "Montgomery", Result.ExpectedValue.SUCCESS);
    }

    private void testCurve(EC_Curve curve, String catName, Result.ExpectedValue expected) {
        Test allocateFirst = runTest(CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), curve.getField()), Result.ExpectedValue.SUCCESS));
        if (!allocateFirst.ok()) {
            doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "No support for " + curve.getBits() + "b " + catName + " curve: " + curve.getId() + ".", allocateFirst));
            return;
        }

        Test set = CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), Result.ExpectedValue.SUCCESS);
        Test generate = setupKeypairs(curve, Result.ExpectedValue.ANY, ECTesterApplet.KEYPAIR_BOTH);
        Test ka = CommandTest.expect(new Command.ECDH(this.card, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, EC_Consts.TRANSFORMATION_NONE, EC_Consts.KeyAgreement_ALG_EC_SVDP_DH), expected);
        Test sig = CommandTest.expect(new Command.ECDSA_sign(this.card, ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.Signature_ALG_ECDSA_SHA, ECTesterApplet.EXPORT_FALSE, null), expected);
        Test perform = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Perform ECDH and ECDSA.", ka, sig);

        if (cfg.cleanup) {
            Test cleanup = CommandTest.expect(new Command.Cleanup(this.card), Result.ExpectedValue.ANY);
            doTest(CompoundTest.greedyAll(Result.ExpectedValue.SUCCESS, "Tests over " + curve.getBits() + "b " + catName + " curve: " + curve.getId() + ".", allocateFirst, set, generate, perform, cleanup));
        } else {
            doTest(CompoundTest.greedyAll(Result.ExpectedValue.SUCCESS, "Tests over " + curve.getBits() + "b " + catName + " curve: " + curve.getId() + ".", allocateFirst, set, generate,  perform));
        }
    }

    private void testCurves(Collection<EC_Curve> curves, String catName, Result.ExpectedValue expected) {
        for (EC_Curve curve : curves) {
            testCurve(curve, catName, expected);
        }
    }
}
