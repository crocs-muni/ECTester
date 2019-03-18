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

import static cz.crcs.ectester.common.test.Result.ExpectedValue;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CardWrongSuite extends CardTestSuite {

    public CardWrongSuite(TestWriter writer, ECTesterReader.Config cfg, CardMngr cardManager) {
        super(writer, cfg, cardManager, "wrong", new String[]{"preset", "random"}, "The wrong curve suite tests whether the card rejects domain parameters which are not curves.");
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
            Test key = runTest(CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), curve.getField()), ExpectedValue.SUCCESS));
            if (!key.ok()) {
                doTest(CompoundTest.all(ExpectedValue.FAILURE, "No support for " + curve.getBits() + "b " + CardUtil.getKeyTypeString(curve.getField()), key));
                continue;
            }
            tests.add(key);
            Test set = runTest(CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), ExpectedValue.FAILURE));
            Test generate = runTest(setupKeypairs(curve, ExpectedValue.SUCCESS, ECTesterApplet.KEYPAIR_BOTH));
            Test setup = runTest(CompoundTest.any(ExpectedValue.SUCCESS, "Set wrong curve and generate keypairs.", set, generate));
            tests.add(setup);

            for (byte kaType : EC_Consts.KA_TYPES) {
                Test allocate = runTest(CommandTest.expect(new Command.AllocateKeyAgreement(this.card, kaType), ExpectedValue.SUCCESS));
                if (allocate.ok()) {
                    Test ka = runTest(CommandTest.expect(new Command.ECDH(this.card, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, EC_Consts.TRANSFORMATION_NONE, kaType), ExpectedValue.FAILURE));
                    Test kaTest = runTest(CompoundTest.all(ExpectedValue.SUCCESS, "Allocate and perform KA.", allocate, ka));
                    tests.add(kaTest);
                }
            }
            doTest(CompoundTest.function((tsts) -> {
                for (int i = 0; i < tsts.length; ++i) {
                    if (i != 1 && !tsts[i].ok()) {
                        return new Result(Result.Value.FAILURE, "Some tests did not have the expected result.");
                    }
                }
                return new Result(Result.Value.SUCCESS, "All tests had the expected result.");
            }, "Wrong curve test of " + curve.getBits() + "b " + CardUtil.getKeyTypeString(curve.getField()), tests.toArray(new Test[0])));
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
            Test key = runTest(CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_BOTH, keyLength, KeyPair.ALG_EC_FP), ExpectedValue.SUCCESS));
            if (!key.ok()) {
                doTest(CompoundTest.all(ExpectedValue.FAILURE, "No support for " + keyLength + "b ALG_EC_FP.", key));
                continue;
            }
            Test set = CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, curve, EC_Consts.PARAMETERS_DOMAIN_FP, null), ExpectedValue.SUCCESS);
            Test setup = CompoundTest.all(ExpectedValue.SUCCESS, "KeyPair setup.", key, set);

            Test prime0 = ecdhTest(new Command.Transform(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.KEY_BOTH, EC_Consts.PARAMETER_FP, EC_Consts.TRANSFORMATION_ZERO), "Set p = 0.", "ECDH with p = 0.");
            Test prime1 = ecdhTest(new Command.Transform(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.KEY_BOTH, EC_Consts.PARAMETER_FP, EC_Consts.TRANSFORMATION_ONE), "Set p = 1.", "ECDH with p = 1.");

            short keyHalf = (short) (keyLength / 2);
            BigInteger prime = new BigInteger(keyHalf, 50, r);
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

            Test wrongPrime = CompoundTest.all(ExpectedValue.SUCCESS, "Tests with corrupted prime parameter.", prime0, prime1, primePower, composite);

            Test resetSetup = CompoundTest.all(ExpectedValue.SUCCESS, "Reset keypair.", set.clone());

            Test randomG = ecdhTest(new Command.Transform(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.KEY_BOTH, EC_Consts.PARAMETER_G, (short) (EC_Consts.TRANSFORMATION_FULLRANDOM | EC_Consts.TRANSFORMATION_04_MASK)), "Set G = random non-point/point-like.", "ECDH with non-point G.");
            Test fullRandomG = ecdhTest(new Command.Transform(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.KEY_BOTH, EC_Consts.PARAMETER_G, EC_Consts.TRANSFORMATION_FULLRANDOM), "Set G = random data.", "ECDH with G = random data.");
            Test zeroG = ecdhTest(new Command.Transform(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.KEY_BOTH, EC_Consts.PARAMETER_G, EC_Consts.TRANSFORMATION_INFINITY), "Set G = inifnity.", "ECDH with G = infinity.");
            Test wrongG = CompoundTest.all(ExpectedValue.SUCCESS, "Tests with corrupted G parameter.", randomG, fullRandomG, zeroG);

            byte[] originalR = new byte[((keyLength + 7) / 8) + 1];
            short origRlen = EC_Consts.getCurveParameter(curve, EC_Consts.PARAMETER_R, originalR, (short) 0);
            if (origRlen != originalR.length) {
                byte[] copyR = new byte[origRlen];
                System.arraycopy(originalR, 0, copyR, 0, origRlen);
                originalR = copyR;
            }
            BigInteger originalBigR = new BigInteger(1, originalR);

            Test zeroR = ecdhTest(new Command.Transform(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, EC_Consts.PARAMETER_R, EC_Consts.TRANSFORMATION_ZERO), "Set R = 0.", "ECDH with R = 0.");
            Test oneR = ecdhTest(new Command.Transform(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, EC_Consts.PARAMETER_R, EC_Consts.TRANSFORMATION_ONE), "Set R = 1.", "ECDH with R = 1.");

            BigInteger prevPrimeR;
            do {
                prevPrimeR = BigInteger.probablePrime(originalBigR.bitLength() - 1, r);
            } while (prevPrimeR.compareTo(originalBigR) >= 0);
            byte[] prevRBytes = ECUtil.toByteArray(prevPrimeR, keyLength);
            EC_Params prevRData = new EC_Params(EC_Consts.PARAMETER_R, new byte[][]{prevRBytes});
            Test prevprimeWrongR = ecdhTest(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, prevRData.getParams(), prevRData.flatten()), "Set R = some prime (but [r]G != infinity) smaller than original R.", "ECDH with wrong R, prevprime.");

            BigInteger nextPrimeR = originalBigR.nextProbablePrime();
            byte[] nextRBytes = ECUtil.toByteArray(nextPrimeR, keyLength);
            EC_Params nextRData = new EC_Params(EC_Consts.PARAMETER_R, new byte[][]{nextRBytes});
            Test nextprimeWrongR = ecdhTest(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, nextRData.getParams(), nextRData.flatten()), "Set R = some prime (but [r]G != infinity) larger than original R.", "ECDH with wrong R, nextprime.");

            byte[] nonprimeRBytes = nextRBytes.clone();
            nonprimeRBytes[nonprimeRBytes.length - 1] ^= 1;
            EC_Params nonprimeWrongRData = new EC_Params(EC_Consts.PARAMETER_R, new byte[][]{nonprimeRBytes});
            Test nonprimeWrongR = ecdhTest(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, nonprimeWrongRData.getParams(), nonprimeWrongRData.flatten()), "Set R = some composite (but [r]G != infinity).", "ECDH with wrong R, composite.");

            Test wrongR = CompoundTest.all(ExpectedValue.SUCCESS, "Tests with corrupted R parameter.", zeroR, oneR, prevprimeWrongR, nextprimeWrongR, nonprimeWrongR);

            byte[] kRaw = new byte[]{(byte) 0xff};
            EC_Params kData = new EC_Params(EC_Consts.PARAMETER_K, new byte[][]{kRaw});
            Test bigK = ecdhTest(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, kData.getParams(), kData.flatten()), "", "");

            byte[] kZero = new byte[]{(byte) 0};
            EC_Params kZeroData = new EC_Params(EC_Consts.PARAMETER_K, new byte[][]{kZero});
            Test zeroK = ecdhTest(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, kZeroData.getParams(), kZeroData.flatten()), "", "");

            Test wrongK = CompoundTest.all(ExpectedValue.SUCCESS, "Tests with corrupted K parameter.", bigK, zeroK);

            doTest(CompoundTest.all(ExpectedValue.SUCCESS, "Tests of " + keyLength + "b " + CardUtil.getKeyTypeString(KeyPair.ALG_EC_FP), setup, wrongPrime, resetSetup, wrongG, resetSetup.clone(), wrongR, resetSetup.clone(), wrongK, resetSetup.clone()));
        }

        /*
         * For binary field:
         *  - e1, e2 or e3 is larger than m.
         *  - e1 = e2 = e3 = 0
         */
        for (short keyLength : EC_Consts.F2M_SIZES) {
            byte curve = EC_Consts.getCurve(keyLength, KeyPair.ALG_EC_F2M);
            Test key = runTest(CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_BOTH, keyLength, KeyPair.ALG_EC_F2M), ExpectedValue.SUCCESS));
            if (!key.ok()) {
                doTest(CompoundTest.all(ExpectedValue.FAILURE, "No support for " + keyLength + "b ALG_EC_F2M.", key));
                continue;
            }
            Test set = CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, curve, EC_Consts.PARAMETERS_DOMAIN_F2M, null), ExpectedValue.SUCCESS);
            Test setup = CompoundTest.all(ExpectedValue.SUCCESS, "KeyPair setup.", key, set);

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

            Test wrong = CompoundTest.all(ExpectedValue.SUCCESS, "Tests with corrupted field polynomial parameter.", coeff0, coeffLarger);
            doTest(CompoundTest.all(ExpectedValue.SUCCESS, "Tests of " + keyLength + "b " + CardUtil.getKeyTypeString(KeyPair.ALG_EC_F2M), setup, wrong));
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
        Test setup = CommandTest.expect(setupCmd, ExpectedValue.FAILURE);
        Test generate = CommandTest.expect(new Command.Generate(this.card, ECTesterApplet.KEYPAIR_BOTH), ExpectedValue.FAILURE);
        Test preparePhase = CompoundTest.any(ExpectedValue.SUCCESS, prepareDesc, setup, generate);
        Test allocateECDH = CommandTest.expect(new Command.AllocateKeyAgreement(this.card, EC_Consts.KeyAgreement_ALG_EC_SVDP_DH), ExpectedValue.SUCCESS);
        Test ecdh = CommandTest.expect(new Command.ECDH(this.card, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.TRANSFORMATION_NONE, EC_Consts.KeyAgreement_ALG_EC_SVDP_DH), ExpectedValue.FAILURE);


        return CompoundTest.function((tests) -> {
            if (preparePhase.ok() | !allocateECDH.ok() | ecdh.ok()) {
                return new Result(Result.Value.SUCCESS, "All tests had the expected result.");
            } else {
                return new Result(Result.Value.FAILURE, "Some tests did not have the expected result.");
            }
        }, (tests) -> {
            preparePhase.run();
            if (preparePhase.ok()) {
                return;
            }
            allocateECDH.run();
            if (!allocateECDH.ok()) {
                return;
            }
            ecdh.run();
        }, fullDesc, preparePhase, allocateECDH, ecdh);
    }
}
