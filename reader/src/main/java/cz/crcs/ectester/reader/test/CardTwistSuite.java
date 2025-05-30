package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.common.ec.EC_Consts;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.ec.EC_Key;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.util.CardConsts;
import cz.crcs.ectester.common.util.CardUtil;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTesterReader;
import cz.crcs.ectester.reader.command.Command;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CardTwistSuite extends CardTestSuite {
    public CardTwistSuite(TestWriter writer, ECTesterReader.Config cfg, CardMngr cardManager) {
        super(writer, cfg, cardManager, "twist",  "The twist test suite tests whether the card correctly rejects points on the quadratic twist of the curve during ECDH.");
    }

    @Override
    protected void runTests() throws Exception {
        Map<String, EC_Key.Public> pubkeys = EC_Store.getInstance().getObjects(EC_Key.Public.class, "twist");
        Map<EC_Curve, List<EC_Key.Public>> curveList = EC_Store.mapKeyToCurve(pubkeys.values());
        for (Map.Entry<EC_Curve, List<EC_Key.Public>> e : curveList.entrySet()) {
            EC_Curve curve = e.getKey();
            List<EC_Key.Public> keys = e.getValue();

            Test allocate = CommandTest.expect(new Command.Allocate(this.card, CardConsts.KEYPAIR_BOTH, curve.getBits(), curve.getField()), Result.ExpectedValue.SUCCESS);
            Test set = CommandTest.expect(new Command.Set(this.card, CardConsts.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), Result.ExpectedValue.SUCCESS);
            Test generate = setupKeypairs(curve, Result.ExpectedValue.SUCCESS, CardConsts.KEYPAIR_LOCAL);

            Test prepare = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Prepare and generate keypair on " + curve.getId() + ".", allocate, set, generate);

            List<Test> ecdhTests = new LinkedList<>();
            for (EC_Key.Public pub : keys) {
                Test setPub = CommandTest.expect(new Command.Set(this.card, CardConsts.KEYPAIR_REMOTE, EC_Consts.CURVE_external, pub.getParams(), pub.flatten()), Result.ExpectedValue.FAILURE);
                Test ecdh = CommandTest.expect(new Command.ECDH(this.card, CardConsts.KEYPAIR_REMOTE, CardConsts.KEYPAIR_LOCAL, CardConsts.EXPORT_FALSE, EC_Consts.TRANSFORMATION_NONE, EC_Consts.KeyAgreement_ALG_EC_SVDP_DH), Result.ExpectedValue.FAILURE, "Card correctly rejected point on twist.", "Card incorrectly accepted point on twist.");
                Test objectEcdh = CompoundTest.any(Result.ExpectedValue.SUCCESS, CardUtil.getKATypeString(EC_Consts.KeyAgreement_ALG_EC_SVDP_DH) + " test with twist pubkey.", setPub, ecdh);
                Command ecdhCommand = new Command.ECDH_direct(this.card, CardConsts.KEYPAIR_LOCAL, CardConsts.EXPORT_FALSE, EC_Consts.TRANSFORMATION_NONE, EC_Consts.KeyAgreement_ALG_EC_SVDP_DH, pub.flatten());
                Test rawEcdh = CommandTest.expect(ecdhCommand, Result.ExpectedValue.FAILURE, "Card correctly rejected point on twist.", "Card incorrectly accepted point on twist.");
                Test test =  CompoundTest.all(Result.ExpectedValue.SUCCESS, pub.getId() + " twist key test.", objectEcdh, rawEcdh);
                for (int i = 0; i < cfg.number; ++i) {
                    ecdhTests.add(test.clone());
                }
            }
            if (cfg.testShuffle)
                Collections.shuffle(ecdhTests);
            Test ecdh = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Perform ECDH with public points on twist.", ecdhTests.toArray(new Test[0]));

            Test tests = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Do tests.", ecdh);
            if (cfg.cleanup) {
                Test cleanup = CommandTest.expect(new Command.Cleanup(this.card), Result.ExpectedValue.ANY);
                doTest(CompoundTest.greedyAllTry(Result.ExpectedValue.SUCCESS, "Twist test of " + curve.getId() + ".", prepare, tests, cleanup));
            } else {
                doTest(CompoundTest.greedyAllTry(Result.ExpectedValue.SUCCESS, "Twist test of " + curve.getId() + ".", prepare, tests));
            }
        }
    }
}
