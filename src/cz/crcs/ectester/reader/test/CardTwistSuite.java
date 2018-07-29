package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.ec.EC_Key;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTesterReader;
import cz.crcs.ectester.reader.command.Command;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CardTwistSuite extends CardTestSuite {
    public CardTwistSuite(TestWriter writer, ECTesterReader.Config cfg, CardMngr cardManager) {
        super(writer, cfg, cardManager, "twist", "The twist test suite tests whether the card correctly rejects points on the quadratic twist of the curve during ECDH.");
    }

    @Override
    protected void runTests() throws Exception {
        Map<String, EC_Key.Public> pubkeys = EC_Store.getInstance().getObjects(EC_Key.Public.class, "twist");
        List<Map.Entry<EC_Curve, List<EC_Key.Public>>> curveList = EC_Store.mapKeyToCurve(pubkeys.values());
        for (Map.Entry<EC_Curve, List<EC_Key.Public>> e : curveList) {
            EC_Curve curve = e.getKey();
            List<EC_Key.Public> keys = e.getValue();

            Test allocate = CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), curve.getField()), Result.ExpectedValue.SUCCESS);
            Test set = CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), Result.ExpectedValue.SUCCESS);
            Test generate = CommandTest.expect(new Command.Generate(this.card, ECTesterApplet.KEYPAIR_LOCAL), Result.ExpectedValue.SUCCESS);

            Test prepare = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Prepare and generate keypair on " + curve.getId(), allocate, set, generate);

            List<Test> ecdhTests = new LinkedList<>();
            for (EC_Key.Public pub : keys) {
                Command ecdhCommand = new Command.ECDH_direct(this.card, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, EC_Consts.TRANSFORMATION_NONE, EC_Consts.KeyAgreement_ALG_EC_SVDP_DH, pub.flatten());
                ecdhTests.add(CommandTest.expect(ecdhCommand, Result.ExpectedValue.FAILURE, "Card correctly rejected point on twist.", "Card incorrectly accepted point on twist."));
            }
            Test ecdh = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Perform ECDH with public points on twist", ecdhTests.toArray(new Test[0]));

            Random r = new Random();
            byte[] raw = new byte[128];
            byte[] sig = new byte[40];
            r.nextBytes(raw);
            r.nextBytes(sig);

            List<Test> ecdsaTests = new LinkedList<>();
            for (EC_Key.Public pub : keys) {
                Command setCommand = new Command.Set(this.card, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, pub.getParams(), pub.flatten());
                Test setTest = CommandTest.expect(setCommand, Result.ExpectedValue.ANY);
                Command ecdsaCommand = new Command.ECDSA_verify(this.card, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.Signature_ALG_ECDSA_SHA, raw, sig);
                Test ecdsaTest = CommandTest.expect(ecdsaCommand, Result.ExpectedValue.FAILURE);
                ecdsaTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Verify random ECDSA signature by " + pub.getId(), setTest, ecdsaTest));
            }
            Test ecdsa = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Verify random ECDSA signature by public points on twist", ecdsaTests.toArray(new Test[0]));

            Test tests = CompoundTest.all(Result.ExpectedValue.SUCCESS, ecdh, ecdsa);
            if (cfg.cleanup) {
                Test cleanup = CommandTest.expect(new Command.Cleanup(this.card), Result.ExpectedValue.SUCCESS);
                doTest(CompoundTest.greedyAllTry(Result.ExpectedValue.SUCCESS, "Twist test of " + curve.getId(), prepare, tests, cleanup));
            } else {
                doTest(CompoundTest.greedyAllTry(Result.ExpectedValue.SUCCESS, "Twist test of " + curve.getId(), prepare, tests));
            }
        }
    }
}
