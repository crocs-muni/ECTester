package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.ec.EC_KAResult;
import cz.crcs.ectester.common.ec.EC_Key;
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
import javacard.security.CryptoException;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CardEdgeCasesSuite extends CardTestSuite {
    public CardEdgeCasesSuite(TestWriter writer, ECTesterReader.Config cfg, CardMngr cardManager) {
        super(writer, cfg, cardManager, "edge-cases", "The edge-cases test suite tests various inputs to ECDH which may cause an implementation to achieve a certain edge-case state during ECDH.\n" +
                "Some of the data is from the google/Wycheproof project. Tests include CVE-2017-10176 and CVE-2017-8932.");
    }

    @Override
    protected void runTests() throws Exception {
        Map<String, EC_KAResult> results = EC_Store.getInstance().getObjects(EC_KAResult.class, "wycheproof");
        List<Map.Entry<String, List<EC_KAResult>>> groupList = EC_Store.mapToPrefix(results.values());
        for (Map.Entry<String, List<EC_KAResult>> e : groupList) {
            String description = null;
            switch (e.getKey()) {
                case "addsub":
                case "cve_2017_10176":
                    description = "Tests for CVE-2017-10176.";
                    break;
                case "cve_2017_8932":
                    description = "Tests for CVE-2017-8932.";
                    break;
            }

            List<Test> groupTests = new LinkedList<>();
            List<Map.Entry<EC_Curve, List<EC_KAResult>>> curveList = EC_Store.mapResultToCurve(e.getValue());
            for (Map.Entry<EC_Curve, List<EC_KAResult>> c : curveList) {
                EC_Curve curve = c.getKey();

                List<Test> curveTests = new LinkedList<>();
                Test allocate = CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), curve.getField()), Result.ExpectedValue.SUCCESS);
                Test set = CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), Result.ExpectedValue.SUCCESS);
                curveTests.add(allocate);
                curveTests.add(set);

                List<EC_KAResult> values = c.getValue();
                for (EC_KAResult value : values) {
                    String id = value.getId();
                    String privkeyId = value.getOneKey();
                    String pubkeyId = value.getOtherKey();

                    EC_Key.Private privkey = EC_Store.getInstance().getObject(EC_Key.Private.class, privkeyId);
                    EC_Key.Public pubkey = EC_Store.getInstance().getObject(EC_Key.Public.class, pubkeyId);

                    Test setPrivkey = CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.CURVE_external, privkey.getParams(), privkey.flatten()), Result.ExpectedValue.SUCCESS);
                    Test setPubkey = CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, pubkey.getParams(), pubkey.flatten()), Result.ExpectedValue.SUCCESS);
                    Test ecdhPreTest = CommandTest.expect(new Command.ECDH(this.card, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, EC_Consts.TRANSFORMATION_NONE, EC_Consts.KeyAgreement_ALG_EC_SVDP_DH), Result.ExpectedValue.SUCCESS);
                    Test ecdh = CommandTest.function(new Command.ECDH(this.card, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_TRUE, EC_Consts.TRANSFORMATION_NONE, value.getJavaCardKA()), new TestCallback<CommandTestable>() {
                        @Override
                        public Result apply(CommandTestable testable) {
                            Response.ECDH dh = (Response.ECDH) testable.getResponse();
                            if (dh.getSW(0) == CryptoException.NO_SUCH_ALGORITHM) {
                                return new Result(Result.Value.SUCCESS, "ECDH algorithm unsupported.");
                            }
                            if (!dh.successful())
                                return new Result(Result.Value.FAILURE, "ECDH was unsuccessful.");
                            if (!dh.hasSecret())
                                return new Result(Result.Value.FAILURE, "ECDH response did not contain the derived secret.");
                            if (!ByteUtil.compareBytes(dh.getSecret(), 0, value.getData(0), 0, dh.secretLength())) {
                                int firstDiff = ByteUtil.diffBytes(dh.getSecret(), 0, value.getData(0), 0, dh.secretLength());
                                System.err.println(ByteUtil.bytesToHex(dh.getSecret()));
                                System.err.println(ByteUtil.bytesToHex(value.getData(0)));
                                return new Result(Result.Value.FAILURE, "ECDH derived secret does not match the test-vector, first difference was at byte " + String.valueOf(firstDiff) + ".");
                            }
                            return new Result(Result.Value.SUCCESS);
                        }
                    });

                    Test one = CompoundTest.greedyAll(Result.ExpectedValue.SUCCESS, "Test " + id + ".", setPrivkey, setPubkey, ecdhPreTest, ecdh);
                    curveTests.add(one);
                }
                groupTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Tests on " + curve.getId() + ".", curveTests.toArray(new Test[0])));
            }
            doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, description, groupTests.toArray(new Test[0])));
        }
    }
}
