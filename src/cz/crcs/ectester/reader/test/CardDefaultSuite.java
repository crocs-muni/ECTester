package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.util.CardUtil;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTesterReader;
import cz.crcs.ectester.reader.command.Command;
import javacard.security.KeyPair;

import java.util.LinkedList;
import java.util.List;

import static cz.crcs.ectester.common.test.Result.ExpectedValue;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CardDefaultSuite extends CardTestSuite {

    public CardDefaultSuite(TestWriter writer, ECTesterReader.Config cfg, CardMngr cardManager) {
        super(writer, cfg, cardManager, "default", "The default test suite run basic support of ECDH and ECDSA.");
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
        for (short keyLength : keySizes) {
            String description = "Tests of " + keyLength + "b " + (field == KeyPair.ALG_EC_FP ? "ALG_EC_FP" : "ALG_EC_F2M") + " support.";

            List<Test> supportTests = new LinkedList<>();
            Test key = runTest(CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_BOTH, keyLength, field), ExpectedValue.SUCCESS));
            if (!key.ok()) {
                doTest(CompoundTest.all(ExpectedValue.SUCCESS, description + " None.", key));
                continue;
            }
            supportTests.add(key);

            Test genDefault = runTest(CommandTest.expect(new Command.Generate(this.card, ECTesterApplet.KEYPAIR_BOTH), ExpectedValue.SUCCESS));
            Test setCustom = runTest(CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.getCurve(keyLength, field), EC_Consts.PARAMETERS_DOMAIN_FP, null), ExpectedValue.SUCCESS));
            Test genCustom = runTest(CommandTest.expect(new Command.Generate(this.card, ECTesterApplet.KEYPAIR_BOTH), ExpectedValue.SUCCESS));
            supportTests.add(genDefault);
            supportTests.add(setCustom);
            supportTests.add(genCustom);

            for (byte kaType : EC_Consts.KA_TYPES) {
                Test allocate = runTest(CommandTest.expect(new Command.AllocateKeyAgreement(this.card, kaType), ExpectedValue.SUCCESS));
                if (allocate.ok()) {
                    Command ecdh = new Command.ECDH(this.card, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_NONE, kaType);
                    Test ka = runTest(CommandTest.expect(ecdh, ExpectedValue.SUCCESS));
                    Test kaCompressed = runTest(CommandTest.expect(new Command.ECDH(this.card, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_COMPRESS, kaType), ExpectedValue.SUCCESS));
                    Test perfTest = null;
                    if (ka.ok()) {
                        perfTest = runTest(PerformanceTest.repeat(ecdh, 10));
                    }
                    Test compound = runTest(CompoundTest.all(ExpectedValue.SUCCESS, "Test of the " + CardUtil.getKATypeString(kaType) + " KeyAgreement.", allocate, ka, kaCompressed, perfTest));
                    supportTests.add(compound);
                } else {
                    runTest(allocate);
                    supportTests.add(allocate);
                }
            }
            for (byte sigType : EC_Consts.SIG_TYPES) {
                Test allocate = runTest(CommandTest.expect(new Command.AllocateSignature(this.card, sigType), ExpectedValue.SUCCESS));
                if (allocate.ok()) {
                    Command ecdsa = new Command.ECDSA(this.card, ECTesterApplet.KEYPAIR_LOCAL, sigType, ECTesterApplet.EXPORT_FALSE, null);
                    Test expect = runTest(CommandTest.expect(ecdsa, ExpectedValue.SUCCESS));
                    Test perfTest = null;
                    if (expect.ok()) {
                        perfTest = runTest(PerformanceTest.repeat(ecdsa, 10));
                    }
                    Test compound = runTest(CompoundTest.all(ExpectedValue.SUCCESS, "Test of the " + CardUtil.getSigTypeString(sigType) + " signature.", allocate, expect, perfTest));
                    supportTests.add(compound);
                } else {
                    supportTests.add(allocate);
                }
            }
            doTest(CompoundTest.all(ExpectedValue.SUCCESS, description + " Some.", supportTests.toArray(new Test[0])));
            new Command.Cleanup(this.card).send();
        }
    }
}
