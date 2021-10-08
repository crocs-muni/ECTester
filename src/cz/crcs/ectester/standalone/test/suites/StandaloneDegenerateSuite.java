package cz.crcs.ectester.standalone.test.suites;

import cz.crcs.ectester.common.cli.TreeCommandLine;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.ec.EC_Key;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.util.ECUtil;
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

/**
 * @author David Hofman
 */
public class StandaloneDegenerateSuite extends StandaloneTestSuite {
    public StandaloneDegenerateSuite(TestWriter writer, ECTesterStandalone.Config cfg, TreeCommandLine cli) {
        super(writer, cfg, cli, "degenerate", "The degenerate suite tests whether the library rejects points outside of the curve during ECDH.",
                "The tested points lie on a part of the plane for which some Edwards, Hessian and Huff form addition formulas degenerate into exponentiation in the base finite field.",
                "Supports options:", "\t - gt/kpg-type", "\t - kt/ka-type (select multiple types by separating them with commas)");
    }

    @Override
    protected void runTests() throws Exception {
        String kpgAlgo = cli.getOptionValue("test.kpg-type");
        String kaAlgo = cli.getOptionValue("test.ka-type");
        List<String> kaTypes = kaAlgo != null ? Arrays.asList(kaAlgo.split(",")) : new ArrayList<>();

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

        Map<String, EC_Key.Public> pubkeys = EC_Store.getInstance().getObjects(EC_Key.Public.class, "degenerate");
        Map<EC_Curve, List<EC_Key.Public>> curveList = EC_Store.mapKeyToCurve(pubkeys.values());
        for (Map.Entry<EC_Curve, List<EC_Key.Public>> e : curveList.entrySet()) {
            EC_Curve curve = e.getKey();
            List<EC_Key.Public> keys = e.getValue();

            KeyPairGenerator kpg = kpgIdent.getInstance(cfg.selected.getProvider());
            ECParameterSpec spec = curve.toSpec();
            KeyGeneratorTestable kgt = new KeyGeneratorTestable(kpg, spec);

            Test generate =  KeyGeneratorTest.expectError(kgt, Result.ExpectedValue.ANY);
            runTest(generate);
            KeyPair kp = kgt.getKeyPair();
            if(kp == null) {
                Test generateFail = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Generating KeyPair has failed on " + curve.getId() + ". " + "KeyAgreement tests will be skipped.", generate);
                doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Degenerate curve test of " + curve.getId() + ".", generateFail));
                continue;
            }
            Test generateSuccess = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Generate keypair.", generate);
            ECPrivateKey ecpriv = (ECPrivateKey) kp.getPrivate();

            List<Test> allKaTests = new LinkedList<>();
            for (KeyAgreementIdent kaIdent : cfg.selected.getKAs()) {
                if (kaAlgo == null || kaIdent.containsAny(kaTypes)) {
                    List<Test> specificKaTests = new LinkedList<>();
                    for (EC_Key.Public pub : keys) {
                        ECPublicKey ecpub = ECUtil.toPublicKey(pub);
                        KeyAgreement ka = kaIdent.getInstance(cfg.selected.getProvider());
                        KeyAgreementTestable testable = new KeyAgreementTestable(ka, ecpriv, ecpub);
                        Test keyAgreement = KeyAgreementTest.expectError(testable, Result.ExpectedValue.FAILURE);
                        specificKaTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, pub.getId() + " degenerate key test.", keyAgreement));
                    }
                    allKaTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Perform " + kaIdent.getName() + " with degenerate public points..", specificKaTests.toArray(new Test[0])));
                }
            }
            if(allKaTests.isEmpty()) {
                allKaTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "None of the specified key agreement types is supported by the library."));
            }
            Test tests = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Do tests.", allKaTests.toArray(new Test[0]));
            doTest(CompoundTest.greedyAllTry(Result.ExpectedValue.SUCCESS, "Degenerate curve test of " + curve.getId() + ".", generateSuccess, tests));
        }
    }
}
