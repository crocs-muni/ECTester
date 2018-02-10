package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.ec.EC_Key;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTesterReader;
import cz.crcs.ectester.reader.command.Command;

import java.util.Map;

import static cz.crcs.ectester.common.test.Result.ExpectedValue;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CardCompositeCurvesSuite extends CardTestSuite {

    public CardCompositeCurvesSuite(TestWriter writer, ECTesterReader.Config cfg, CardMngr cardManager) {
        super(writer, cfg, cardManager, "composite", "The composite suite runs ECDH over curves with composite order. This should generally fail, as using such a curve is unsafe.");
    }

    @Override
    protected void runTests() throws Exception {
        /* Do the default run with the public keys set to provided smallorder keys
         * over composite order curves. Essentially small subgroup attacks.
         * These should fail, the curves aren't safe so that if the computation with
         * a small order public key succeeds the private key modulo the public key order
         * is revealed.
         */
        Map<String, EC_Key> keys = EC_Store.getInstance().getObjects(EC_Key.class, "composite");
        for (EC_Key key : keys.values()) {
            EC_Curve curve = EC_Store.getInstance().getObject(EC_Curve.class, key.getCurve());
            Test allocate = CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), curve.getField()), ExpectedValue.SUCCESS);
            Test set = CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), ExpectedValue.ANY);
            Test generate = CommandTest.expect(new Command.Generate(this.card, ECTesterApplet.KEYPAIR_LOCAL), ExpectedValue.ANY);
            Command ecdhCommand = new Command.ECDH_direct(this.card, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_NONE, ECTesterApplet.KeyAgreement_ALG_EC_SVDP_DH, key.flatten());
            Test ecdh = CommandTest.expect(ecdhCommand, ExpectedValue.FAILURE, "Card correctly rejected to do ECDH over a composite order curve.", "Card incorrectly does ECDH over a composite order curve, leaks bits of private key.");

            doTest(CompoundTest.greedyAll(ExpectedValue.SUCCESS, "Composite test of " + curve.getId() + ", " + key.getDesc(), allocate, set, generate, ecdh));
            new Command.Cleanup(this.card).send();
        }
    }
}
