package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.util.CardUtil;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTesterReader;
import cz.crcs.ectester.reader.command.Command;
import javacard.security.KeyPair;

import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static cz.crcs.ectester.common.test.Result.ExpectedValue;
import static cz.crcs.ectester.common.test.Result.Value;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CardDefaultSuite extends CardTestSuite {

    public CardDefaultSuite(TestWriter writer, ECTesterReader.Config cfg, CardMngr cardManager) {
        super(writer, cfg, cardManager, "default", null, "The default test suite tests basic support and performance of ECDH and ECDSA.");
    }

    @Override
    protected void runTests() throws Exception {
        if (cfg.primeField) {
            runDefault(KeyPair.ALG_EC_FP);
        }
        if (cfg.binaryField) {
            runDefault(KeyPair.ALG_EC_F2M);
        }
    }

    private void runDefault(byte field) throws Exception {
        short[] keySizes = field == KeyPair.ALG_EC_FP ? EC_Consts.FP_SIZES : EC_Consts.F2M_SIZES;
        short domain = field == KeyPair.ALG_EC_FP ? EC_Consts.PARAMETERS_DOMAIN_FP : EC_Consts.PARAMETERS_DOMAIN_F2M;
        for (short keyLength : keySizes) {

            List<Test> supportTests = new LinkedList<>();
            Test allocateFirst = runTest(CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_BOTH, keyLength, field), ExpectedValue.SUCCESS));
            if (!allocateFirst.ok()) {
                doTest(CompoundTest.all(ExpectedValue.SUCCESS, "No support for " + keyLength + "b " + CardUtil.getKeyTypeString(field) + ".", allocateFirst));
                continue;
            }
            supportTests.add(allocateFirst);

            Test genDefault = runTest(CommandTest.expect(new Command.Generate(this.card, ECTesterApplet.KEYPAIR_BOTH), ExpectedValue.SUCCESS));
            Test allocateSecond = runTest(CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_BOTH, keyLength, field), ExpectedValue.SUCCESS));
            Test setCustom = runTest(CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.getCurve(keyLength, field), domain, null), ExpectedValue.SUCCESS));
            Test genCustom = runTest(CommandTest.expect(new Command.Generate(this.card, ECTesterApplet.KEYPAIR_BOTH), ExpectedValue.SUCCESS));
            supportTests.add(genDefault);
            supportTests.add(allocateSecond);
            supportTests.add(setCustom);
            supportTests.add(genCustom);

            List<Test> kaTests = new LinkedList<>();
            for (byte kaType : EC_Consts.KA_TYPES) {
                Test allocate = runTest(CommandTest.expect(new Command.AllocateKeyAgreement(this.card, kaType), ExpectedValue.SUCCESS));
                if (allocate.ok()) {
                    Command ecdh = new Command.ECDH(this.card, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.TRANSFORMATION_NONE, kaType);
                    Test ka = runTest(CommandTest.expect(ecdh, ExpectedValue.SUCCESS));
                    Test kaCompressed = runTest(CommandTest.expect(new Command.ECDH(this.card, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.TRANSFORMATION_COMPRESS, kaType), ExpectedValue.SUCCESS));

                    String kaDesc = "Test of the " + CardUtil.getKATypeString(kaType) + " KeyAgreement.";
                    Function<Test[], Result> kaCallback = (tests) -> {
                        if (tests[1].ok() || tests[2].ok()) {
                            return new Result(Value.SUCCESS, "Some ECDH is supported.");
                        } else {
                            return new Result(Value.FAILURE, "ECDH failed.");
                        }
                    };

                    Test compound;
                    if (ka.ok()) {
                        Test perfTest = runTest(PerformanceTest.repeat(this.card, ecdh, 10));
                        compound = runTest(CompoundTest.function(kaCallback, kaDesc, allocate, ka, kaCompressed, perfTest));
                    } else {
                        compound = runTest(CompoundTest.function(kaCallback, kaDesc, allocate, ka, kaCompressed));
                    }

                    kaTests.add(compound);
                } else {
                    runTest(allocate);
                    kaTests.add(allocate);
                }
            }
            Test kaTest = runTest(CompoundTest.any(ExpectedValue.SUCCESS, "KeyAgreement tests.", kaTests.toArray(new Test[0])));
            supportTests.add(kaTest);

            List<Test> signTests = new LinkedList<>();
            for (byte sigType : EC_Consts.SIG_TYPES) {
                Test allocate = runTest(CommandTest.expect(new Command.AllocateSignature(this.card, sigType), ExpectedValue.SUCCESS));
                if (allocate.ok()) {
                    Command ecdsa = new Command.ECDSA(this.card, ECTesterApplet.KEYPAIR_LOCAL, sigType, ECTesterApplet.EXPORT_FALSE, null);
                    Test expect = runTest(CommandTest.expect(ecdsa, ExpectedValue.SUCCESS));

                    String signDesc = "Test of the " + CardUtil.getSigTypeString(sigType) + " signature.";

                    Random rand = new Random();
                    byte[] sigData = new byte[64];
                    rand.nextBytes(sigData);

                    Test compound;
                    if (expect.ok()) {
                        Command ecdsaSign = new Command.ECDSA_sign(this.card, ECTesterApplet.KEYPAIR_LOCAL, sigType, ECTesterApplet.EXPORT_TRUE, sigData);
                        PerformanceTest signTest = runTest(PerformanceTest.repeat(this.card, "Sign", ecdsaSign, 10));
                        byte[] signature = signTest.getResponses()[0].getParam(0);
                        Command ecdsaVerify = new Command.ECDSA_verify(this.card, ECTesterApplet.KEYPAIR_LOCAL, sigType, sigData, signature);
                        PerformanceTest verifyTest = runTest(PerformanceTest.repeat(this.card, "Verify", ecdsaVerify, 10));
                        compound = runTest(CompoundTest.all(ExpectedValue.SUCCESS, signDesc, allocate, expect, signTest, verifyTest));
                    } else {
                        compound = runTest(CompoundTest.all(ExpectedValue.SUCCESS, signDesc, allocate, expect));
                    }
                    signTests.add(compound);
                } else {
                    signTests.add(allocate);
                }
            }
            Test signTest = runTest(CompoundTest.any(ExpectedValue.SUCCESS, "Signature tests.", signTests.toArray(new Test[0])));
            supportTests.add(signTest);
            ExpectedValue[] testExpects = {ExpectedValue.SUCCESS, ExpectedValue.ANY, ExpectedValue.SUCCESS, ExpectedValue.SUCCESS, ExpectedValue.SUCCESS, ExpectedValue.SUCCESS, ExpectedValue.SUCCESS};
            List<ExpectedValue> expects = Stream.of(testExpects).collect(Collectors.toList());
            if (cfg.cleanup) {
                supportTests.add(CommandTest.expect(new Command.Cleanup(this.card), Result.ExpectedValue.ANY));
                expects.add(ExpectedValue.ANY);
            }

            doTest(CompoundTest.mask(expects.toArray(new ExpectedValue[0]), "Tests of " + keyLength + "b " + CardUtil.getKeyTypeString(field) + " support.", supportTests.toArray(new Test[0])));
        }
    }
}
