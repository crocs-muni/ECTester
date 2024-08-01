package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.common.ec.EC_Consts;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.util.CardConsts;
import cz.crcs.ectester.common.util.CardUtil;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTesterReader;
import cz.crcs.ectester.reader.command.Command;

import java.util.LinkedList;
import java.util.List;
import java.util.function.Consumer;
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
            runDefault(EC_Consts.ALG_EC_FP);
        }
        if (cfg.binaryField) {
            runDefault(EC_Consts.ALG_EC_F2M);
        }
    }

    private void runDefault(byte field) throws Exception {
        short[] keySizes = field == EC_Consts.ALG_EC_FP ? EC_Consts.FP_SIZES : EC_Consts.F2M_SIZES;
        short domain = field == EC_Consts.ALG_EC_FP ? EC_Consts.PARAMETERS_DOMAIN_FP : EC_Consts.PARAMETERS_DOMAIN_F2M;
        for (short keyLength : keySizes) {
            List<Test> supportTests = new LinkedList<>();
            Test allocateFirst = CommandTest.expect(new Command.Allocate(this.card, CardConsts.KEYPAIR_BOTH, keyLength, field), ExpectedValue.SUCCESS);
            Test genDefault = CommandTest.expect(new Command.Generate(this.card, CardConsts.KEYPAIR_BOTH), ExpectedValue.SUCCESS);
            Test allocateSecond = CommandTest.expect(new Command.Allocate(this.card, CardConsts.KEYPAIR_BOTH, keyLength, field), ExpectedValue.SUCCESS);
            Test setCustom = CommandTest.expect(new Command.Set(this.card, CardConsts.KEYPAIR_BOTH, EC_Consts.getCurve(keyLength, field), domain, null), ExpectedValue.SUCCESS);
            Test genCustom = CommandTest.expect(new Command.Generate(this.card, CardConsts.KEYPAIR_BOTH), ExpectedValue.SUCCESS);
            supportTests.add(allocateFirst);
            supportTests.add(genDefault);
            supportTests.add(allocateSecond);
            supportTests.add(setCustom);
            supportTests.add(genCustom);

            List<Test> kaTests = new LinkedList<>();
            for (byte kaType : EC_Consts.KA_TYPES) {
                Test allocate = CommandTest.expect(new Command.AllocateKeyAgreement(this.card, kaType), ExpectedValue.SUCCESS);
                Command ecdh = new Command.ECDH(this.card, CardConsts.KEYPAIR_LOCAL, CardConsts.KEYPAIR_REMOTE, CardConsts.EXPORT_FALSE, EC_Consts.TRANSFORMATION_NONE, kaType);
                Test ka = CommandTest.expect(ecdh, ExpectedValue.SUCCESS);
                Test kaCompressed = CommandTest.expect(new Command.ECDH(this.card, CardConsts.KEYPAIR_LOCAL, CardConsts.KEYPAIR_REMOTE, CardConsts.EXPORT_FALSE, EC_Consts.TRANSFORMATION_COMPRESS, kaType), ExpectedValue.SUCCESS);

                String kaDesc = "Test of the " + CardUtil.getKATypeString(kaType) + " KeyAgreement.";
                Function<Test[], Result> kaCallback = (tests) -> {
                    if (tests[1].ok() || tests[2].ok()) {
                        return new Result(Value.SUCCESS, "Some ECDH is supported.");
                    } else {
                        return new Result(Value.FAILURE, "ECDH failed.");
                    }
                };

                Consumer<Test[]> runCallback = tests -> {
                    for (Test t : tests) {
                        if (t instanceof PerformanceTest) {
                            if (tests[0].ok() && tests[1].ok()) {
                                t.run();
                            }
                        } else {
                            t.run();
                        }
                    }
                };

                Test perfTest = PerformanceTest.repeat(this.card, ecdh, 10);
                Test compound = CompoundTest.function(kaCallback, runCallback, kaDesc, allocate, ka, kaCompressed, perfTest);
                kaTests.add(compound);
            }
            Test kaTest = CompoundTest.any(ExpectedValue.SUCCESS, "KeyAgreement tests.", kaTests.toArray(new Test[0]));
            supportTests.add(kaTest);

            List<Test> signTests = new LinkedList<>();
            for (byte sigType : EC_Consts.SIG_TYPES) {
                Test allocate = CommandTest.expect(new Command.AllocateSignature(this.card, sigType), ExpectedValue.SUCCESS);
                Command ecdsa = new Command.ECDSA(this.card, CardConsts.KEYPAIR_LOCAL, sigType, CardConsts.EXPORT_FALSE, null);
                Test sign = CommandTest.expect(ecdsa, ExpectedValue.SUCCESS);

                String signDesc = "Test of the " + CardUtil.getSigTypeString(sigType) + " signature.";

                byte[] sigData = new byte[]{(byte) domain, sigType};

                Function<Test[], Result> sigCallback = (tests) -> {
                    if (tests[1].ok()) {
                        return new Result(Value.SUCCESS, "Some ECDSA is supported.");
                    } else {
                        return new Result(Value.FAILURE, "ECDSA failed.");
                    }
                };
                Consumer<Test[]> runCallback = tests -> {
                    for (Test t : tests) {
                        if (t instanceof PerformanceTest) {
                            if (tests[0].ok() && tests[1].ok()) {
                                t.run();
                            }
                        } else {
                            t.run();
                        }
                    }
                };

                Command ecdsaSign = new Command.ECDSA_sign(this.card, CardConsts.KEYPAIR_LOCAL, sigType, CardConsts.EXPORT_TRUE, sigData);
                PerformanceTest signTest = PerformanceTest.repeat(this.card, "Sign", ecdsaSign, 10);

                CommandTestable.FunctionCommandTestable verifyTestable = new CommandTestable.FunctionCommandTestable(() -> new Command.ECDSA_verify(this.card, CardConsts.KEYPAIR_LOCAL, sigType, sigData, signTest.getResponses()[0].getParam(0)));
                PerformanceTest verifyTest = PerformanceTest.repeat(this.card, "Verify", verifyTestable, 10);
                Test compound = CompoundTest.function(sigCallback, runCallback, signDesc, allocate, sign, signTest, verifyTest);
                signTests.add(compound);
            }
            Test signTest = CompoundTest.any(ExpectedValue.SUCCESS, "Signature tests.", signTests.toArray(new Test[0]));
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
