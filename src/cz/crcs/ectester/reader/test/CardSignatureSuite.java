package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.ec.EC_Key;
import cz.crcs.ectester.common.ec.EC_SigResult;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTesterReader;
import cz.crcs.ectester.reader.command.Command;

import java.util.List;
import java.util.Map;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CardSignatureSuite extends CardTestSuite {
    public CardSignatureSuite(TestWriter writer, ECTesterReader.Config cfg, CardMngr cardManager) {
        super(writer, cfg, cardManager, "signature", null, "The signature test suite tests verifying various malformed and well-formed but invalid ECDSA signatures.");
    }

    @Override
    protected void runTests() throws Exception {
        Map<String, EC_SigResult> results = EC_Store.getInstance().getObjects(EC_SigResult.class, "wrong");
        Map<String, List<EC_SigResult>> groups = EC_Store.mapToPrefix(results.values());

        List<EC_SigResult> nok = groups.entrySet().stream().filter((e) -> e.getKey().equals("nok")).findFirst().get().getValue();

        byte[] data = "Some stuff that is not the actual data".getBytes();
        for (EC_SigResult sig : nok) {
            ecdsaTest(sig, Result.ExpectedValue.FAILURE, data);
        }

        List<EC_SigResult> ok = groups.entrySet().stream().filter((e) -> e.getKey().equals("ok")).findFirst().get().getValue();
        for (EC_SigResult sig : ok) {
            ecdsaTest(sig, Result.ExpectedValue.SUCCESS, null);
        }
    }

    private void ecdsaTest(EC_SigResult sig, Result.ExpectedValue expected, byte[] defaultData) {
        EC_Key.Public pubkey = EC_Store.getInstance().getObject(EC_Key.Public.class, sig.getVerifyKey());

        byte[] data = sig.getSigData();
        if (data == null) {
            data = defaultData;
        }

        EC_Curve curve = EC_Store.getInstance().getObject(EC_Curve.class, sig.getCurve());
        Test allocate = CommandTest.expect(new Command.Allocate(this.card, ECTesterApplet.KEYPAIR_LOCAL, curve.getBits(), curve.getField()), Result.ExpectedValue.SUCCESS);
        Test set = CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), Result.ExpectedValue.SUCCESS);
        Test setVerifyKey = CommandTest.expect(new Command.Set(this.card, ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.CURVE_external, pubkey.getParams(), pubkey.flatten()), Result.ExpectedValue.SUCCESS);
        Test ecdsaVerify = CommandTest.expect(new Command.ECDSA_verify(this.card, ECTesterApplet.KEYPAIR_LOCAL, sig.getJavaCardSig(), data, sig.getData(0)), expected);

        if (cfg.cleanup) {
            Test cleanup = CommandTest.expect(new Command.Cleanup(this.card), Result.ExpectedValue.ANY);
            doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "ECDSA test of " + sig.getId() + ".", allocate, set, setVerifyKey, ecdsaVerify, cleanup));
        } else {
            doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "ECDSA test of " + sig.getId() + ".", allocate, set, setVerifyKey, ecdsaVerify));
        }

    }
}
