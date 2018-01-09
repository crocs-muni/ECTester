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
        for (short keyLength : EC_Consts.FP_SIZES) {
            Test key = doTest(CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_BOTH, keyLength, field), ExpectedValue.SUCCESS));
            if (!key.ok()) {
                continue;
            }
            doTest(CommandTest.expect(new Command.Generate(this.card, ECTesterApplet.KEYPAIR_BOTH), ExpectedValue.SUCCESS));
            doTest(CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.getCurve(keyLength, field), EC_Consts.PARAMETERS_DOMAIN_FP, null), ExpectedValue.SUCCESS));
            doTest(CommandTest.expect(new Command.Generate(this.card, ECTesterApplet.KEYPAIR_BOTH), ExpectedValue.SUCCESS));
            for (byte kaType : EC_Consts.KA_TYPES) {
                Test allocate = CommandTest.expect(new Command.AllocateKeyAgreement(this.card, kaType), ExpectedValue.SUCCESS);
                allocate.run();
                if (allocate.ok()) {
                    Test ka = CommandTest.expect(new Command.ECDH(this.card, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_NONE, kaType), ExpectedValue.SUCCESS);
                    ka.run();
                    Test kaCompressed = CommandTest.expect(new Command.ECDH(this.card, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_COMPRESS, kaType), ExpectedValue.SUCCESS);
                    kaCompressed.run();
                    doTest(CompoundTest.all(ExpectedValue.SUCCESS, "Test of the " + CardUtil.getKATypeString(kaType) + " KeyAgreement.", allocate, ka, kaCompressed));
                }
            }
            for (byte sigType : EC_Consts.SIG_TYPES) {
                Test allocate = doTest(CommandTest.expect(new Command.AllocateSignature(this.card, sigType), ExpectedValue.SUCCESS));
                if (allocate.ok()) {
                    doTest(CommandTest.expect(new Command.ECDSA(this.card, ECTesterApplet.KEYPAIR_LOCAL, sigType, ECTesterApplet.EXPORT_FALSE, null), ExpectedValue.SUCCESS));
                }
            }
        }
    }
}
