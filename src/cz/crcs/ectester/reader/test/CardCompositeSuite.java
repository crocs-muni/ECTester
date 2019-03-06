package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.ec.EC_Key;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.util.CardUtil;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTesterReader;
import cz.crcs.ectester.reader.command.Command;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static cz.crcs.ectester.common.test.Result.ExpectedValue;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CardCompositeSuite extends CardTestSuite {

    public CardCompositeSuite(TestWriter writer, ECTesterReader.Config cfg, CardMngr cardManager) {
        super(writer, cfg, cardManager, "composite", new String[]{"preset", "random"}, "The composite suite runs ECDH over curves with composite order.",
                "Various types of compositeness is tested: smooth numbers, Carmichael pseudo-prime, prime square, product of two large primes.");
    }

    @Override
    protected void runTests() throws Exception {
        Map<String, EC_Key> keys = EC_Store.getInstance().getObjects(EC_Key.class, "composite");
        Map<EC_Curve, List<EC_Key>> mappedKeys = EC_Store.mapKeyToCurve(keys.values());
        for (Map.Entry<EC_Curve, List<EC_Key>> curveKeys : mappedKeys.entrySet()) {
            EC_Curve curve = curveKeys.getKey();
            List<Test> tests = new LinkedList<>();
            Test allocate = runTest(CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_LOCAL, curve.getBits(), curve.getField()), ExpectedValue.SUCCESS));
            if (!allocate.ok()) {
                doTest(CompoundTest.all(ExpectedValue.SUCCESS, "No support for " + curve.getBits() + "b " + CardUtil.getKeyTypeString(curve.getField()) + ".", allocate));
                continue;
            }
            tests.add(allocate);
            tests.add(CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), ExpectedValue.ANY));

            String name;
            if (cfg.testOptions.contains("preset")) {
                name = "preset semi-random private key";
            } else {
                name = "generated private key";
            }
            tests.add(setupKeypairs(curve, ExpectedValue.ANY, ECTesterApplet.KEYPAIR_LOCAL));
            for (EC_Key key : curveKeys.getValue()) {
                Command ecdhCommand = new Command.ECDH_direct(this.card, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, EC_Consts.TRANSFORMATION_NONE, EC_Consts.KeyAgreement_ALG_EC_SVDP_DH, key.flatten());
                Test ecdh = CommandTest.expect(ecdhCommand, ExpectedValue.FAILURE, "Card correctly rejected to do ECDH over a composite order curve.", "Card incorrectly does ECDH over a composite order curve, leaks bits of private key.");
                tests.add(CompoundTest.greedyAllTry(ExpectedValue.SUCCESS, "Composite test of " + curve.getId() + ", with " + name + ", " + key.getDesc(), ecdh));
            }
            doTest(CompoundTest.all(ExpectedValue.SUCCESS, "Composite test of " + curve.getId() + ".", tests.toArray(new Test[0])));
        }


        Map<String, EC_Curve> results = EC_Store.getInstance().getObjects(EC_Curve.class, "composite");
        Map<String, List<EC_Curve>> groups = EC_Store.mapToPrefix(results.values());
        /* Test the whole curves with both keypairs generated on card(no small-order public points provided).
         */
        List<EC_Curve> wholeCurves = groups.entrySet().stream().filter((e) -> e.getKey().equals("whole")).findFirst().get().getValue();
        testGroup(wholeCurves, "Composite generator order", ExpectedValue.FAILURE, "Card rejected to do ECDH with composite order generator.", "Card did not reject to do ECDH with composite order generator.");

        /* Also test having a G of small order, so small R.
         */
        List<EC_Curve> smallRCurves = groups.entrySet().stream().filter((e) -> e.getKey().equals("small")).findFirst().get().getValue();
        testGroup(smallRCurves, "Small generator order", ExpectedValue.FAILURE, "Card correctly rejected to do ECDH over a small order generator.", "Card incorrectly does ECDH over a small order generator.");

        /* Test increasingly larger prime R, to determine where/if card behavior changes.
         */
        List<EC_Curve> varyingCurves = groups.entrySet().stream().filter((e) -> e.getKey().equals("varying")).findFirst().get().getValue();
        testGroup(varyingCurves, null, ExpectedValue.ANY, "", "");

        /* Also test having a G of large but composite order, R = p * q,
         */
        List<EC_Curve> pqCurves = groups.entrySet().stream().filter((e) -> e.getKey().equals("pq")).findFirst().get().getValue();
        testGroup(pqCurves, null, ExpectedValue.ANY, "", "");

        /* Also test having G or large order being a Carmichael pseudoprime, R = p * q * r,
         */
        List<EC_Curve> ppCurves = groups.entrySet().stream().filter((e) -> e.getKey().equals("pp")).findFirst().get().getValue();
        testGroup(ppCurves, "Generator order = Carmichael pseudo-prime", ExpectedValue.ANY, "", "");

        /* Also test rg0 curves.
         */
        List<EC_Curve> rg0Curves = groups.entrySet().stream().filter((e) -> e.getKey().equals("rg0")).findFirst().get().getValue();
        testGroup(rg0Curves, null, ExpectedValue.ANY, "", "");
    }

    private void testGroup(List<EC_Curve> curves, String testName, ExpectedValue dhValue, String ok, String nok) throws Exception {
        for (EC_Curve curve : curves) {
            Test allocate = CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), curve.getField()), ExpectedValue.SUCCESS);
            Test set = CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), ExpectedValue.ANY);
            Test generate = setupKeypairs(curve, ExpectedValue.ANY, ECTesterApplet.KEYPAIR_BOTH);
            Test ecdh = CommandTest.expect(new Command.ECDH(this.card, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, EC_Consts.TRANSFORMATION_NONE, EC_Consts.KeyAgreement_ALG_EC_SVDP_DH), dhValue, ok, nok);
            Test ecdsa = CommandTest.expect(new Command.ECDSA_sign(this.card, ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.Signature_ALG_ECDSA_SHA, ECTesterApplet.EXPORT_FALSE, null), dhValue, ok, nok);

            String description;
            if (testName == null) {
                description = curve.getDesc() + " test of " + curve.getId() + ".";
            } else {
                description = testName + " test of " + curve.getId() + ".";
            }

            Test perform = CompoundTest.all(ExpectedValue.SUCCESS, "Perform ECDH and ECDSA.", ecdh, ecdsa);

            if (cfg.cleanup) {
                Test cleanup = CommandTest.expect(new Command.Cleanup(this.card), ExpectedValue.ANY);
                doTest(CompoundTest.greedyAllTry(ExpectedValue.SUCCESS, description, allocate, set, generate, perform, cleanup));
            } else {
                doTest(CompoundTest.greedyAllTry(ExpectedValue.SUCCESS, description, allocate, set, generate, perform));
            }
        }

    }
}
