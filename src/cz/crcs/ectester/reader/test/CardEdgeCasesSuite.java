package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.ec.EC_KAResult;
import cz.crcs.ectester.common.ec.EC_Key;
import cz.crcs.ectester.common.ec.EC_Params;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.test.TestCallback;
import cz.crcs.ectester.common.util.ByteUtil;
import cz.crcs.ectester.common.util.ECUtil;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTesterReader;
import cz.crcs.ectester.reader.command.Command;
import cz.crcs.ectester.reader.response.Response;
import javacard.security.CryptoException;
import javacard.security.KeyPair;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CardEdgeCasesSuite extends CardTestSuite {
    public CardEdgeCasesSuite(TestWriter writer, ECTesterReader.Config cfg, CardMngr cardManager) {
        super(writer, cfg, cardManager, "edge-cases", "The edge-cases test suite tests various inputs to ECDH which may cause an implementation to achieve a certain edge-case state during it.",
                "Some of the data is from the google/Wycheproof project. Tests include CVE-2017-10176 and CVE-2017-8932.",
                "Various edge private key values are also tested.");
    }

    @Override
    protected void runTests() throws Exception {
        Map<String, EC_KAResult> results = EC_Store.getInstance().getObjects(EC_KAResult.class, "wycheproof");
        List<Map.Entry<String, List<EC_KAResult>>> groupList = EC_Store.mapToPrefix(results.values());
        for (Map.Entry<String, List<EC_KAResult>> e : groupList) {
            String description = null;
            switch (e.getKey()) {
                case "addsub":
                    description = "Tests for addition-subtraction chains.";
                    break;
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
                Test prepareCurve = CompoundTest.greedyAll(Result.ExpectedValue.SUCCESS, "Prepare curve", allocate, set);

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

                    Test prepare = CompoundTest.greedyAll(Result.ExpectedValue.SUCCESS, "Prepare", setPrivkey, setPubkey);
                    Test ka = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Do", ecdhPreTest, ecdh);

                    Test one = CompoundTest.greedyAllTry(Result.ExpectedValue.SUCCESS, "Test " + id + ".", prepare, ka);
                    curveTests.add(one);
                }

                Test curveTest = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Tests", curveTests.toArray(new Test[0]));
                groupTests.add(CompoundTest.greedyAllTry(Result.ExpectedValue.SUCCESS, "Tests on " + curve.getId() + ".", prepareCurve, curveTest));
            }
            doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, description, groupTests.toArray(new Test[0])));
        }

        Map<String, EC_Curve> curveMap = EC_Store.getInstance().getObjects(EC_Curve.class, "secg");
        List<EC_Curve> curves = curveMap.entrySet().stream().filter((e) -> e.getKey().endsWith("r1") && e.getValue().getField() == KeyPair.ALG_EC_FP).map(Map.Entry::getValue).collect(Collectors.toList());
        curves.add(EC_Store.getInstance().getObject(EC_Curve.class, "cofactor/cofactor128p2"));
        curves.add(EC_Store.getInstance().getObject(EC_Curve.class, "cofactor/cofactor160p4"));
        Random rand = new Random();
        for (EC_Curve curve : curves) {
            Test key = runTest(CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), KeyPair.ALG_EC_FP), Result.ExpectedValue.SUCCESS));
            if (!key.ok()) {
                doTest(CompoundTest.all(Result.ExpectedValue.FAILURE, "No support for " + curve.getBits() + "b ALG_EC_FP.", key));
                continue;
            }
            Test set = CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), Result.ExpectedValue.SUCCESS);
            Test generate = CommandTest.expect(new Command.Generate(this.card, ECTesterApplet.KEYPAIR_LOCAL), Result.ExpectedValue.SUCCESS);
            Test setup = CompoundTest.all(Result.ExpectedValue.SUCCESS, "KeyPair setup.", key, set, generate);

            Test zeroS = ecdhTest(new Command.Transform(this.card, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, EC_Consts.PARAMETER_S, EC_Consts.TRANSFORMATION_ZERO), "ECDH with S = 0.", Result.ExpectedValue.FAILURE, Result.ExpectedValue.FAILURE);
            Test oneS = ecdhTest(new Command.Transform(this.card, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, EC_Consts.PARAMETER_S, EC_Consts.TRANSFORMATION_ONE), "ECDH with S = 1.", Result.ExpectedValue.FAILURE, Result.ExpectedValue.FAILURE);

            byte[] rParam = curve.getParam(EC_Consts.PARAMETER_R)[0];
            BigInteger R = new BigInteger(1, rParam);
            BigInteger smaller = new BigInteger(curve.getBits(), rand).mod(R);
            BigInteger diff = R.divide(BigInteger.valueOf(10));
            BigInteger randDiff = new BigInteger(diff.bitLength(), rand).mod(diff);
            BigInteger larger = R.add(randDiff);

            BigInteger full = BigInteger.valueOf(1).shiftLeft(R.bitLength() - 1).subtract(BigInteger.ONE);

            EC_Params fullParams = makeParams(full);
            Test fullS = ecdhTest(new Command.Set(this.card, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, fullParams.getParams(), fullParams.flatten()), "ECDH with S = 2^((log2 r) - 1) - 1.", Result.ExpectedValue.SUCCESS, Result.ExpectedValue.SUCCESS);

            EC_Params smallerParams = makeParams(smaller);
            Test smallerS = ecdhTest(new Command.Set(this.card, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, smallerParams.getParams(), smallerParams.flatten()), "ECDH with S < r.", Result.ExpectedValue.SUCCESS, Result.ExpectedValue.SUCCESS);

            EC_Params exactParams = makeParams(R);
            Test exactS = ecdhTest(new Command.Set(this.card, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, exactParams.getParams(), exactParams.flatten()), "ECDH with S = r.", Result.ExpectedValue.FAILURE, Result.ExpectedValue.FAILURE);

            EC_Params largerParams = makeParams(larger);
            Test largerS = ecdhTest(new Command.Set(this.card, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, largerParams.getParams(), largerParams.flatten()), "ECDH with S > r.", Result.ExpectedValue.ANY, Result.ExpectedValue.ANY);

            BigInteger rm1 = R.subtract(BigInteger.ONE);
            BigInteger rp1 = R.add(BigInteger.ONE);

            EC_Params rm1Params = makeParams(rm1);
            Test rm1S = ecdhTest(new Command.Set(this.card, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, rm1Params.getParams(), rm1Params.flatten()), "ECDH with S = r - 1.", Result.ExpectedValue.SUCCESS, Result.ExpectedValue.SUCCESS);

            EC_Params rp1Params = makeParams(rp1);
            Test rp1S = ecdhTest(new Command.Set(this.card, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, rp1Params.getParams(), rp1Params.flatten()), "ECDH with S = r + 1.", Result.ExpectedValue.ANY, Result.ExpectedValue.ANY);

            byte[] k = curve.getParam(EC_Consts.PARAMETER_K)[0];
            BigInteger K = new BigInteger(1, k);
            BigInteger kr = K.multiply(R);
            BigInteger krm1 = kr.subtract(BigInteger.ONE);
            BigInteger krp1 = kr.add(BigInteger.ONE);

            EC_Params krParams = makeParams(kr);
            Test krS /*ONE!*/ = ecdhTest(new Command.Set(this.card, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, krParams.getParams(), krParams.flatten()), "ECDH with S = k * r.", Result.ExpectedValue.FAILURE, Result.ExpectedValue.FAILURE);

            EC_Params krm1Params = makeParams(krm1);
            Test krm1S = ecdhTest(new Command.Set(this.card, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, krm1Params.getParams(), krm1Params.flatten()), "ECDH with S = (k * r) - 1.", Result.ExpectedValue.FAILURE, Result.ExpectedValue.FAILURE);

            EC_Params krp1Params = makeParams(krp1);
            Test krp1S = ecdhTest(new Command.Set(this.card, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, krp1Params.getParams(), krp1Params.flatten()), "ECDH with S = (k * r) + 1.", Result.ExpectedValue.FAILURE, Result.ExpectedValue.FAILURE);

            if (cfg.cleanup) {
                Test cleanup = CommandTest.expect(new Command.Cleanup(this.card), Result.ExpectedValue.ANY);
                doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Tests with edge-case private key values over " + curve.getId() + ".", setup, zeroS, oneS, fullS, smallerS, exactS, largerS, rm1S, rp1S, krS, krm1S, krp1S, cleanup));
            } else {
                doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Tests with edge-case private key values over " + curve.getId() + ".", setup, zeroS, oneS, fullS, smallerS, exactS, largerS, rm1S, rp1S, krS, krm1S, krp1S));
            }
        }

        EC_Curve secp160r1 = EC_Store.getInstance().getObject(EC_Curve.class, "secg/secp160r1");
        byte[] pData = secp160r1.getParam(EC_Consts.PARAMETER_FP)[0];
        BigInteger p = new BigInteger(1, pData);
        byte[] rData = secp160r1.getParam(EC_Consts.PARAMETER_R)[0];
        BigInteger r = new BigInteger(1, rData);

        BigInteger range = r.subtract(p);
        BigInteger deviation = range.divide(BigInteger.valueOf(5));
        BigDecimal dev = new BigDecimal(deviation);
        BigDecimal smallDev = new BigDecimal(10000);
        int n = 10;
        BigInteger[] rs = new BigInteger[n];
        BigInteger[] ps = new BigInteger[n];
        BigInteger[] zeros = new BigInteger[n];
        for (int i = 0; i < n; ++i) {
            double sample;
            do {
                sample = rand.nextGaussian();
            } while (sample >= -1 && sample <= 1);
            BigInteger where = dev.multiply(new BigDecimal(sample)).toBigInteger();
            rs[i] = where.add(r);
            ps[i] = where.add(p);
            zeros[i] = smallDev.multiply(new BigDecimal(sample)).toBigInteger().abs();
        }
        Arrays.sort(rs);
        Arrays.sort(ps);
        Arrays.sort(zeros);

        Test key = runTest(CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_BOTH, secp160r1.getBits(), KeyPair.ALG_EC_FP), Result.ExpectedValue.SUCCESS));
        if (!key.ok()) {
            doTest(CompoundTest.all(Result.ExpectedValue.FAILURE, "No support for " + secp160r1.getBits() + "b ALG_EC_FP.", key));
            return;
        }
        Test set = CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, secp160r1.getParams(), secp160r1.flatten()), Result.ExpectedValue.SUCCESS);
        Test generate = CommandTest.expect(new Command.Generate(this.card, ECTesterApplet.KEYPAIR_LOCAL), Result.ExpectedValue.SUCCESS);
        Test setup = CompoundTest.all(Result.ExpectedValue.SUCCESS, "KeyPair setup.", key, set, generate);

        Test[] zeroTests = new Test[n];
        int i = 0;
        for (BigInteger nearZero : zeros) {
            EC_Params params = makeParams(nearZero);
            zeroTests[i++] = ecdhTest(new Command.Set(this.card, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, params.getParams(), params.flatten()), nearZero.toString(16), Result.ExpectedValue.ANY, Result.ExpectedValue.ANY);
        }
        Test zeroTest = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Near zero.", zeroTests);

        Test[] pTests = new Test[n];
        i = 0;
        for (BigInteger nearP : ps) {
            EC_Params params = makeParams(nearP);
            pTests[i++] = ecdhTest(new Command.Set(this.card, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, params.getParams(), params.flatten()), nearP.toString(16) + (nearP.compareTo(p) > 0 ? " (>p)" : " (<=p)"), Result.ExpectedValue.ANY, Result.ExpectedValue.ANY);
        }
        Test pTest = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Near p.", pTests);

        Test[] rTests = new Test[n];
        i = 0;
        for (BigInteger nearR : rs) {
            EC_Params params = makeParams(nearR);
            rTests[i++] = ecdhTest(new Command.Set(this.card, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, params.getParams(), params.flatten()), nearR.toString(16) + (nearR.compareTo(r) > 0 ? " (>r)" : " (<=r)"), Result.ExpectedValue.ANY, Result.ExpectedValue.ANY);
        }
        Test rTest = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Near r.", rTests);
        doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Test private key values near zero, near p and near/larger than the order.", setup, zeroTest, pTest, rTest));
    }

    private Test ecdhTest(Command setPriv, String desc, Result.ExpectedValue setExpect, Result.ExpectedValue ecdhExpect) {
        Test set = CommandTest.expect(setPriv, setExpect);
        Test ecdh = CommandTest.expect(new Command.ECDH(this.card, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_TRUE, EC_Consts.TRANSFORMATION_NONE, EC_Consts.KeyAgreement_ALG_EC_SVDP_DH), ecdhExpect);

        return CompoundTest.any(Result.ExpectedValue.SUCCESS, desc, set, ecdh);
    }

    private EC_Params makeParams(BigInteger s) {
        return makeParams(ECUtil.toByteArray(s, s.bitLength()));
    }

    private EC_Params makeParams(byte[] s) {
        return new EC_Params(EC_Consts.PARAMETER_S, new byte[][]{s});
    }
}
