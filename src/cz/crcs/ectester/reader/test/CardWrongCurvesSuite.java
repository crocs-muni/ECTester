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
import javacard.security.KeyPair;

import java.util.Map;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CardWrongCurvesSuite extends CardTestSuite {

    public CardWrongCurvesSuite(TestWriter writer, ECTesterReader.Config cfg, CardMngr cardManager) {
        super(writer, cfg, cardManager, "wrong", "The wrong curve suite run whether the card rejects domain parameters which are not curves.");
    }

    @Override
    protected void runTests() throws Exception {
        /* Just do the default run on the wrong curves.
         * These should generally fail, the curves aren't curves.
         */
        Map<String, EC_Curve> curves = EC_Store.getInstance().getObjects(EC_Curve.class, "wrong");
        for (Map.Entry<String, EC_Curve> e : curves.entrySet()) {
            EC_Curve curve = e.getValue();
            if (curve.getBits() != cfg.bits && !cfg.all) {
                continue;
            }
            if (curve.getField() == KeyPair.ALG_EC_FP && !cfg.primeField || curve.getField() == KeyPair.ALG_EC_F2M && !cfg.binaryField) {
                continue;
            }
            Test key = doTest(CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), curve.getField()), Result.ExpectedValue.SUCCESS));
            if (!key.ok()) {
                continue;
            }
            Test set = runTest(CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), Result.ExpectedValue.SUCCESS));
            Test generate = runTest(CommandTest.expect(new Command.Generate(this.card, ECTesterApplet.KEYPAIR_BOTH), Result.ExpectedValue.SUCCESS));
            doTest(CompoundTest.any(Result.ExpectedValue.FAILURE, "Set wrong curve and generate keypairs, should fail." ,set, generate));

            for (byte kaType : EC_Consts.KA_TYPES) {
                Test allocate = runTest(CommandTest.expect(new Command.AllocateKeyAgreement(this.card, kaType), Result.ExpectedValue.SUCCESS));
                if (allocate.ok()) {
                    Test ka = runTest(CommandTest.expect(new Command.ECDH(this.card, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_NONE, kaType), Result.ExpectedValue.FAILURE));
                    doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Allocate and perform KA, should fail.", allocate, ka));
                }
            }
        }
    }
}
