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

public class StandaloneTwistSuite extends StandaloneTestSuite {
    public StandaloneTwistSuite(TestWriter writer, ECTesterStandalone.Config cfg, TreeCommandLine cli) {
        super(writer, cfg, cli, "twist", "The twist test suite tests whether the library correctly rejects points on the quadratic twist of the curve during ECDH.", "Supports options:", "\t - gt/kpg-type", "\t - kt/ka-type (select multiple types by separating them with commas)");
    }

    @Override
    protected void runTests() throws Exception {
        String kpgAlgo = cli.getOptionValue("test.kpg-type");
        String kaAlgo = cli.getOptionValue("test.ka-type");

        List<String> kaTypes;
        if(kaAlgo != null) {
            kaTypes = Arrays.asList(kaAlgo.split(","));
        } else {
            kaTypes = new ArrayList<>();
        }

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

        Map<String, EC_Key.Public> pubkeys = EC_Store.getInstance().getObjects(EC_Key.Public.class, "twist");
        Map<EC_Curve, List<EC_Key.Public>> curveList = EC_Store.mapKeyToCurve(pubkeys.values());
        for (Map.Entry<EC_Curve, List<EC_Key.Public>> e : curveList.entrySet()) {
            EC_Curve curve = e.getKey();
            List<EC_Key.Public> keys = e.getValue();

            KeyPairGenerator kpg = kpgIdent.getInstance(cfg.selected.getProvider());
            ECParameterSpec spec = curve.toSpec();
            KeyGeneratorTestable kgt = new KeyGeneratorTestable(kpg, spec);

            Test generate = CompoundTest.all(Result.ExpectedValue.SUCCESS,"Generate keypair.", KeyGeneratorTest.expect(kgt, Result.ExpectedValue.SUCCESS));
            runTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Generate keypair on " + curve.getId() + ".", generate));

            KeyPair kp = kgt.getKeyPair();
            if(kp == null) {
                Test generateFail = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Generating keypair has failed on " + curve.getId() + ".", generate);
                doTest(doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Twist test of " + curve.getId() + ".", generateFail)));
                continue;
            }
            ECPrivateKey ecpriv = (ECPrivateKey) kp.getPrivate();

            List<Test> allKaTests = new LinkedList<>();
            for (KeyAgreementIdent kaIdent : cfg.selected.getKAs()) {
                if (kaAlgo == null || kaIdent.containsAny(kaTypes)) {
                    KeyAgreement ka = kaIdent.getInstance(cfg.selected.getProvider());

                    List<Test> specificKaTests = new LinkedList<>();
                    for (EC_Key.Public pub : keys) {
                        ECPublicKey ecpub = ECUtil.toPublicKey(pub);
                        KeyAgreementTestable testable = new KeyAgreementTestable(ka, ecpriv, ecpub);
                        Test keyAgreement = KeyAgreementTest.expect(testable, Result.ExpectedValue.FAILURE);
                        specificKaTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, pub.getId() + " twist key test.", keyAgreement));
                    }
                    allKaTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Perform " + kaIdent.getName() + " with public points on twist.", specificKaTests.toArray(new Test[0])));
                }
            }
            Test tests = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Do tests.", allKaTests.toArray(new Test[0]));
            doTest(CompoundTest.greedyAllTry(Result.ExpectedValue.SUCCESS, "Twist test of " + curve.getId() + ".", generate, tests));
        }
    }
}
