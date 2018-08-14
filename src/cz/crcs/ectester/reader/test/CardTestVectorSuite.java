package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.ec.*;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.test.TestCallback;
import cz.crcs.ectester.common.util.ByteUtil;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTesterReader;
import cz.crcs.ectester.reader.command.Command;
import cz.crcs.ectester.reader.response.Response;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static cz.crcs.ectester.common.test.Result.ExpectedValue;
import static cz.crcs.ectester.common.test.Result.Value;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CardTestVectorSuite extends CardTestSuite {

    public CardTestVectorSuite(TestWriter writer, ECTesterReader.Config cfg, CardMngr cardManager) {
        super(writer, cfg, cardManager, "test", "The test-vectors suite contains a collection of test vectors which test basic ECDH correctness.");
    }

    @Override
    protected void runTests() throws Exception {
        /* Set original curves (secg/nist/brainpool). Set keypairs from test vectors.
         * Do ECDH both ways, export and verify that the result is correct.
         */
        Map<String, EC_KAResult> results = EC_Store.getInstance().getObjects(EC_KAResult.class, "test");
        for (EC_KAResult result : results.values()) {
            EC_Curve curve = EC_Store.getInstance().getObject(EC_Curve.class, result.getCurve());
            EC_Params onekey = EC_Store.getInstance().getObject(EC_Keypair.class, result.getOneKey());
            if (onekey == null) {
                onekey = EC_Store.getInstance().getObject(EC_Key.Private.class, result.getOneKey());
            }
            EC_Params otherkey = EC_Store.getInstance().getObject(EC_Keypair.class, result.getOtherKey());
            if (otherkey == null) {
                otherkey = EC_Store.getInstance().getObject(EC_Key.Public.class, result.getOtherKey());
            }
            if (onekey == null || otherkey == null) {
                throw new IOException("Test vector keys couldn't be located.");
            }
            List<Test> testVector = new LinkedList<>();

            testVector.add(CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), curve.getField()), ExpectedValue.SUCCESS));
            testVector.add(CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), ExpectedValue.SUCCESS));
            testVector.add(CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.CURVE_external, EC_Consts.PARAMETER_S, onekey.flatten(EC_Consts.PARAMETER_S)), ExpectedValue.SUCCESS));
            testVector.add(CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, EC_Consts.PARAMETER_W, otherkey.flatten(EC_Consts.PARAMETER_W)), ExpectedValue.SUCCESS));
            testVector.add(CommandTest.function(new Command.ECDH(this.card, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_TRUE, EC_Consts.TRANSFORMATION_NONE, result.getJavaCardKA()), new TestCallback<CommandTestable>() {
                @Override
                public Result apply(CommandTestable testable) {
                    Response.ECDH dh = (Response.ECDH) testable.getResponse();
                    if (!dh.successful())
                        return new Result(Value.FAILURE, "ECDH was unsuccessful.");
                    if (!dh.hasSecret())
                        return new Result(Value.FAILURE, "ECDH response did not contain the derived secret.");
                    if (!ByteUtil.compareBytes(dh.getSecret(), 0, result.getData(0), 0, dh.secretLength())) {
                        int firstDiff = ByteUtil.diffBytes(dh.getSecret(), 0, result.getData(0), 0, dh.secretLength());
                        return new Result(Value.FAILURE, "ECDH derived secret does not match the test-vector, first difference was at byte " + String.valueOf(firstDiff) + ".");
                    }
                    return new Result(Value.SUCCESS);
                }
            }));
            if (cfg.cleanup) {
                testVector.add(CommandTest.expect(new Command.Cleanup(this.card), ExpectedValue.ANY));
            }
            doTest(CompoundTest.greedyAll(ExpectedValue.SUCCESS, "Test vector " + result.getId(), testVector.toArray(new Test[0])));
        }
    }
}
