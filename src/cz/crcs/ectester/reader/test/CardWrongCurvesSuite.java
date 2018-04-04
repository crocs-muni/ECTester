package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.ec.EC_Params;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.util.ByteUtil;
import cz.crcs.ectester.common.util.CardUtil;
import cz.crcs.ectester.common.util.ECUtil;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTesterReader;
import cz.crcs.ectester.reader.command.Command;
import javacard.security.KeyPair;

import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;

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
            List<Test> tests = new LinkedList<>();
            Test key = runTest(CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), curve.getField()), Result.ExpectedValue.SUCCESS));
            if (!key.ok()) {
                doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "No support for " + curve.getBits() + "b " + CardUtil.getKeyTypeString(curve.getField()), key));
                continue;
            }
            tests.add(key);
            Test set = runTest(CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), Result.ExpectedValue.SUCCESS));
            Test generate = runTest(CommandTest.expect(new Command.Generate(this.card, ECTesterApplet.KEYPAIR_BOTH), Result.ExpectedValue.SUCCESS));
            Test setup = runTest(CompoundTest.any(Result.ExpectedValue.FAILURE, "Set wrong curve and generate keypairs, should fail.", set, generate));
            tests.add(setup);

            for (byte kaType : EC_Consts.KA_TYPES) {
                Test allocate = runTest(CommandTest.expect(new Command.AllocateKeyAgreement(this.card, kaType), Result.ExpectedValue.SUCCESS));
                if (allocate.ok()) {
                    Test ka = runTest(CommandTest.expect(new Command.ECDH(this.card, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.TRANSFORMATION_NONE, kaType), Result.ExpectedValue.FAILURE));
                    Test kaTest = runTest(CompoundTest.all(Result.ExpectedValue.FAILURE, "Allocate and perform KA, should fail.", allocate, ka));
                    tests.add(kaTest);
                }
            }
            doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Wrong curve test of " + curve.getBits() + "b " + CardUtil.getKeyTypeString(curve.getField()), tests.toArray(new Test[0])));
        }
        /*
         * Do some interesting tests with corrupting the custom curves.
         * For prime field:
         *  - p = 0
         *  - p = 1
         *  - p is a square of a prime
         *  - p is a composite q * s with q, s primes
         *  - TODO: p divides discriminant
         */
        Random r = new Random();
        for (short keyLength : EC_Consts.FP_SIZES) {
            byte curve = EC_Consts.getCurve(keyLength, KeyPair.ALG_EC_FP);
            Test key = runTest(CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_BOTH, keyLength, KeyPair.ALG_EC_FP), Result.ExpectedValue.SUCCESS));
            if (!key.ok()) {
                continue;
            }
            Test set = runTest(CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, curve, EC_Consts.PARAMETERS_DOMAIN_FP, null), Result.ExpectedValue.SUCCESS));
            Test setup = runTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "KeyPair setup.", key, set));

            Test prime0 = ecdhTest(new Command.Transform(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.KEY_BOTH, EC_Consts.PARAMETER_FP, EC_Consts.TRANSFORMATION_ZERO), "Set p = 0.", "ECDH with p = 0.");
            Test prime1 = ecdhTest(new Command.Transform(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.KEY_BOTH, EC_Consts.PARAMETER_FP, EC_Consts.TRANSFORMATION_ONE), "Set p = 1.", "ECDH with p = 1.");

            short keyHalf = (short) (keyLength / 2);
            BigInteger prime = new BigInteger(keyHalf, r);
            BigInteger primePow = prime.pow(2);
            byte[] primePowBytes = ECUtil.toByteArray(primePow, keyLength);
            EC_Params primePowData = new EC_Params(EC_Consts.PARAMETER_FP, new byte[][]{primePowBytes});
            Test primePower = ecdhTest(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, primePowData.getParams(), primePowData.flatten()), "Set p = square of a prime.", "ECDH with p = q^2.");

            BigInteger q = new BigInteger(keyHalf, r);
            BigInteger s = new BigInteger(keyHalf, r);
            BigInteger compositeValue = q.multiply(s);
            byte[] compositeBytes = ECUtil.toByteArray(compositeValue, keyLength);
            EC_Params compositeData = new EC_Params(EC_Consts.PARAMETER_FP, new byte[][]{compositeBytes});
            Test composite = ecdhTest(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, compositeData.getParams(), compositeData.flatten()), "Set p = product of two primes.", "ECDH with p = q * s.");

            Test wrong = runTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Tests with corrupted prime parameter.", prime0, prime1, primePower, composite));
            doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Tests of " + keyLength + "b " + CardUtil.getKeyTypeString(KeyPair.ALG_EC_FP), setup, wrong));
        }

        /*
         * For binary field:
         *  - e1, e2 or e3 is larger than m.
         *  - e1 = e2 = e3 = 0
         */
        for (short keyLength : EC_Consts.F2M_SIZES) {
            byte curve = EC_Consts.getCurve(keyLength, KeyPair.ALG_EC_F2M);
            Test key = runTest(CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_BOTH, keyLength, KeyPair.ALG_EC_F2M), Result.ExpectedValue.SUCCESS));
            if (!key.ok()) {
                continue;
            }
            Test set = runTest(CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, curve, EC_Consts.PARAMETERS_DOMAIN_F2M, null), Result.ExpectedValue.SUCCESS));
            Test setup = runTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "KeyPair setup.", key, set));

            Test coeff0 = ecdhTest(new Command.Transform(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.KEY_BOTH, EC_Consts.PARAMETER_F2M, EC_Consts.TRANSFORMATION_ZERO), "Set e1 = e2 = e3 = 0.", "ECDH with wrong field polynomial: x^" + keyLength);

            short e1 = (short) (2 * keyLength);
            short e2 = (short) (3 * keyLength);
            short e3 = (short) (4 * keyLength);
            byte[][] coeffBytes = new byte[][]{
                    ByteUtil.shortToBytes(keyLength),
                    ByteUtil.shortToBytes(e1),
                    ByteUtil.shortToBytes(e2),
                    ByteUtil.shortToBytes(e3)};
            EC_Params coeffParams = new EC_Params(EC_Consts.PARAMETER_F2M, coeffBytes);
            Test coeffLarger = ecdhTest(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, coeffParams.getParams(), coeffParams.flatten()), "Set e1=" + e1 + ", e2=" + e2 + ", e3=" + e3, "ECDH with wrong field poly, powers larger than " + keyLength);

            Test wrong = runTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Tests with corrupted field polynomial parameter.", coeff0, coeffLarger));
            doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Tests of " + keyLength + "b " + CardUtil.getKeyTypeString(KeyPair.ALG_EC_F2M), setup, wrong));
        }

        /*
         * TODO: tests for both Fp and F2m:
         *  - generator not on curve,
         *  - generator not on proper subgroup of curve(as specified by order/cofactor),
         *  - wrong order,
         *  - wrong cofactor.
         */
    }

    private Test ecdhTest(Command setupCmd, String prepareDesc, String fullDesc) {
        Test setup = runTest(CommandTest.expect(setupCmd, Result.ExpectedValue.FAILURE));
        Test generate = runTest(CommandTest.expect(new Command.Generate(this.card, ECTesterApplet.KEYPAIR_BOTH), Result.ExpectedValue.FAILURE));
        Test preparePhase = runTest(CompoundTest.any(Result.ExpectedValue.SUCCESS, prepareDesc, setup, generate));
        Test allocateECDH = runTest(CommandTest.expect(new Command.AllocateKeyAgreement(this.card, EC_Consts.KeyAgreement_ALG_EC_SVDP_DH), Result.ExpectedValue.SUCCESS));
        Test ecdh = runTest(CommandTest.expect(new Command.ECDH(this.card, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.TRANSFORMATION_NONE, EC_Consts.KeyAgreement_ALG_EC_SVDP_DH), Result.ExpectedValue.FAILURE));
        return runTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, fullDesc, preparePhase, allocateECDH, ecdh));
    }
}
