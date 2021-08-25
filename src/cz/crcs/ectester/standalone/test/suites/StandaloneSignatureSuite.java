package cz.crcs.ectester.standalone.test.suites;

import cz.crcs.ectester.common.cli.TreeCommandLine;
import cz.crcs.ectester.common.ec.EC_Key;
import cz.crcs.ectester.common.ec.EC_SigResult;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.util.ECUtil;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.standalone.ECTesterStandalone;
import cz.crcs.ectester.standalone.consts.SignatureIdent;
import cz.crcs.ectester.standalone.test.base.SignatureTest;
import cz.crcs.ectester.standalone.test.base.SignatureTestable;

import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.util.*;

/**
 * @author David Hofman
 */
public class StandaloneSignatureSuite extends StandaloneTestSuite {
    public StandaloneSignatureSuite(TestWriter writer, ECTesterStandalone.Config cfg, TreeCommandLine cli) {
        super(writer, cfg, cli, "signature", "The signature test suite tests verifying various malformed and well-formed but invalid ECDSA signatures.",
                "Supports options:", "\t - st/sig-type");
    }

    @Override
    protected void runTests() throws Exception {
        String sigAlgo = cli.getOptionValue("test.sig-type");

        SignatureIdent sigIdent;
        if (sigAlgo == null) {
            // try ECDSA, if not, fail with: need to specify sig algo.
            Optional<SignatureIdent> sigIdentOpt = cfg.selected.getSigs().stream()
                    .filter((ident) -> ident.contains("ECDSA"))
                    .findFirst();
            if (sigIdentOpt.isPresent()) {
                sigIdent = sigIdentOpt.get();
            } else {
                System.err.println("The default Signature algorithm type of \"ECDSA\" was not found. Need to specify a type.");
                return;
            }
        } else {
            // try the specified, if not, fail with: wrong sig algo/not found.
            Optional<SignatureIdent> sigIdentOpt = cfg.selected.getSigs().stream()
                    .filter((ident) -> ident.contains(sigAlgo))
                    .findFirst();
            if (sigIdentOpt.isPresent()) {
                sigIdent = sigIdentOpt.get();
            } else {
                System.err.println("The Signature algorithm type of \"" + sigAlgo + "\" was not found.");
                return;
            }
        }

        Map<String, EC_SigResult> results = EC_Store.getInstance().getObjects(EC_SigResult.class, "wrong");
        Map<String, List<EC_SigResult>> groups = EC_Store.mapToPrefix(results.values());

        List<EC_SigResult> nok = groups.entrySet().stream().filter((e) -> e.getKey().equals("nok")).findFirst().get().getValue();

        byte[] data = "Some stuff that is not the actual data".getBytes();
        for (EC_SigResult sig : nok) {
            ecdsaTest(sig, sigIdent, Result.ExpectedValue.FAILURE, data);
        }

        List<EC_SigResult> ok = groups.entrySet().stream().filter((e) -> e.getKey().equals("ok")).findFirst().get().getValue();
        for (EC_SigResult sig : ok) {
            ecdsaTest(sig, sigIdent, Result.ExpectedValue.SUCCESS, null);
        }
    }

    private void ecdsaTest(EC_SigResult sig, SignatureIdent sigIdent, Result.ExpectedValue expected, byte[] defaultData) throws NoSuchAlgorithmException {
        ECPublicKey ecpub = ECUtil.toPublicKey(EC_Store.getInstance().getObject(EC_Key.Public.class, sig.getVerifyKey()));

        byte[] data = sig.getSigData();
        if (data == null) {
            data = defaultData;
        }

        Signature signature = sigIdent.getInstance(cfg.selected.getProvider());
        SignatureTestable testable = new SignatureTestable(signature, ecpub, data, sig.getData(0));
        doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "ECDSA test of " + sig.getId() + ".", SignatureTest.expectError(testable, expected)));
    }
}
