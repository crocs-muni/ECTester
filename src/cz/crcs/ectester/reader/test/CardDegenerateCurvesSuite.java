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

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CardDegenerateCurvesSuite extends CardTestSuite {

    public CardDegenerateCurvesSuite(TestWriter writer, ECTesterReader.Config cfg, CardMngr cardManager) {
        super(writer, cfg, cardManager, "degenerate", "The degenerate suite tests whether the card rejects points outside of the curve during ECDH.",
                "The tested points lie on a part of the plane for which some Edwards, Hessian and Huff form addition formulas work.");
    }

    @Override
    protected void runTests() throws Exception {
        Map<String, EC_Key.Public> pubkeys = EC_Store.getInstance().getObjects(EC_Key.Public.class, "degenerate");
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
                ecdhTests.add(CommandTest.expect(ecdhCommand, Result.ExpectedValue.FAILURE, "Card correctly rejected point on degenerate curve.", "Card incorrectly accepted point on degenerate curve."));
            }
            Test ecdh = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Perform ECDH with degenerate public points", ecdhTests.toArray(new Test[0]));

            doTest(CompoundTest.greedyAllTry(Result.ExpectedValue.SUCCESS, "Degenerate curve test of " + curve.getId(), prepare, ecdh));
            new Command.Cleanup(this.card).send();
        }
    }
}
