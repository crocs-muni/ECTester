package cz.crcs.ectester.standalone.test.suites;

import cz.crcs.ectester.common.cli.TreeCommandLine;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.util.CardUtil;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.standalone.ECTesterStandalone;
import cz.crcs.ectester.standalone.consts.KeyAgreementIdent;
import cz.crcs.ectester.standalone.consts.KeyPairGeneratorIdent;
import cz.crcs.ectester.standalone.test.base.KeyAgreementTest;
import cz.crcs.ectester.standalone.test.base.KeyAgreementTestable;
import cz.crcs.ectester.standalone.test.base.KeyGeneratorTest;
import cz.crcs.ectester.standalone.test.base.KeyGeneratorTestable;

import javax.crypto.KeyAgreement;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.*;

public class StandaloneWrongSuite extends StandaloneTestSuite {
    private String kpgAlgo;
    private String kaAlgo;
    private String sigAlgo;
    private List<String> kaTypes;
    private List<String> sigTypes;

    public StandaloneWrongSuite(TestWriter writer, ECTesterStandalone.Config cfg, TreeCommandLine cli) {
        super(writer, cfg, cli, "wrong", "The wrong curve suite tests whether the library rejects domain parameters which are not curves.",
                "Supports options:",
                "\t - gt/kpg-type",
                "\t - kt/ka-type (select multiple types by separating them with commas)",
                "\t - st/sig-type (select multiple types by separating them with commas)");
    }


    @Override
    protected void runTests() throws Exception {
        kpgAlgo = cli.getOptionValue("test.kpg-type");
        kaAlgo = cli.getOptionValue("test.ka-type");
        sigAlgo = cli.getOptionValue("test.sig-type");
        kaTypes = kaAlgo != null ? Arrays.asList(kaAlgo.split(",")) : new ArrayList<>();
        sigTypes = sigAlgo != null ? Arrays.asList(sigAlgo.split(",")) : new ArrayList<>();

        KeyPairGeneratorIdent kpgIdent;
        if (kpgAlgo == null) {
            // try EC, if not, fail with: need to specify kpg algo.
            Optional<KeyPairGeneratorIdent> kpgIdentOpt = cfg.selected.getKPGs().stream()
                    .filter((ident) -> ident.contains("EC"))
                    .findFirst();
            if (kpgIdentOpt.isPresent()) {
                kpgIdent = kpgIdentOpt.get();
            } else {
                System.err.println("The default KeyPairGenerator algorithm type of \"EC\" was not found. Need to specify a type.");
                return;
            }
        } else {
            // try the specified, if not, fail with: wrong kpg algo/not found.
            Optional<KeyPairGeneratorIdent> kpgIdentOpt = cfg.selected.getKPGs().stream()
                    .filter((ident) -> ident.contains(kpgAlgo))
                    .findFirst();
            if (kpgIdentOpt.isPresent()) {
                kpgIdent = kpgIdentOpt.get();
            } else {
                System.err.println("The KeyPairGenerator algorithm type of \"" + kpgAlgo + "\" was not found.");
                return;
            }
        }
        KeyPairGenerator kpg = kpgIdent.getInstance(cfg.selected.getProvider());

        /* Just do the default run on the wrong curves.
         * These should generally fail, the curves aren't curves.
         */
        Map<String, EC_Curve> curves = EC_Store.getInstance().getObjects(EC_Curve.class, "wrong");
        for (Map.Entry<String, EC_Curve> e : curves.entrySet()) {
            EC_Curve curve = e.getValue();
            ECParameterSpec spec = curve.toSpec();

            //try generating a keypair
            KeyGeneratorTestable kgt = new KeyGeneratorTestable(kpg, spec);
            Test generate =  KeyGeneratorTest.expectError(kgt, Result.ExpectedValue.ANY);
            runTest(generate);
            KeyPair kp = kgt.getKeyPair();
            if(kp == null) {
                Test generateFail = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Generating KeyPair has failed on " + curve.getBits() + "b " + CardUtil.getKeyTypeString(curve.getField()), generate);
                doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Wrong curve test of " + curve.getBits() + "b " + CardUtil.getKeyTypeString(curve.getField()), generateFail));
                continue;
            }
            Test generateSuccess = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Generate keypair.", generate);
            ECPrivateKey ecpriv = (ECPrivateKey) kp.getPrivate();
            ECPublicKey ecpub = (ECPublicKey) kp.getPublic();

            //try all the specified kas
            List<Test> kaTests = new LinkedList<>();
            for (KeyAgreementIdent kaIdent : cfg.selected.getKAs()) {
                if (kaAlgo == null || kaIdent.containsAny(kaTypes)) {
                    KeyAgreement ka = kaIdent.getInstance(cfg.selected.getProvider());
                    KeyAgreementTestable testable = new KeyAgreementTestable(ka, ecpriv, ecpub);
                    kaTests.add(KeyAgreementTest.expectError(testable, Result.ExpectedValue.FAILURE));
                }
            }
            if(kaTests.isEmpty()) {
                kaTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "None of the specified KeyAgreement types is supported by the library."));
            }
            Test performKeyAgreements = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Perform specified KeyAgreements.", kaTests.toArray(new Test[0]));
            doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Wrong curve test of " + curve.getBits() + "b " + CardUtil.getKeyTypeString(curve.getField()), generateSuccess, performKeyAgreements));
        }
    }
}
