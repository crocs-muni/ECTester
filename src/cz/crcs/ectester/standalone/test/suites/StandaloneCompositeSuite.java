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
import cz.crcs.ectester.standalone.consts.SignatureIdent;
import cz.crcs.ectester.standalone.test.base.*;

import javax.crypto.KeyAgreement;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.*;

/**
 * @author David Hofman
 */
public class StandaloneCompositeSuite extends StandaloneTestSuite {
    private String kpgAlgo;
    private String kaAlgo;
    private String sigAlgo;
    private List<String> kaTypes;
    private List<String> sigTypes;

    public StandaloneCompositeSuite(TestWriter writer, ECTesterStandalone.Config cfg, TreeCommandLine cli) {
        super(writer, cfg, cli, "composite", "The composite suite runs ECDH over curves with composite order.",
                "Various types of compositeness is tested: smooth numbers, Carmichael pseudo-prime, prime square, product of two large primes.",
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

        Map<String, EC_Key.Public> keys = EC_Store.getInstance().getObjects(EC_Key.Public.class, "composite");
        Map<EC_Curve, List<EC_Key.Public>> mappedKeys = EC_Store.mapKeyToCurve(keys.values());
        for (Map.Entry<EC_Curve, List<EC_Key.Public>> curveKeys : mappedKeys.entrySet()) {
            EC_Curve curve = curveKeys.getKey();
            ECParameterSpec spec = curve.toSpec();

            //Generate KeyPair
            KeyGeneratorTestable kgt = new KeyGeneratorTestable(kpg, spec);
            Test generate =  KeyGeneratorTest.expectError(kgt, Result.ExpectedValue.ANY);
            runTest(generate);
            KeyPair kp = kgt.getKeyPair();
            if(kp == null) {
                Test generateFail = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Generating KeyPair has failed on " + curve.getId() + ". " + "KeyAgreement tests will be skipped.", generate);
                doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Composite test of " + curve.getId() + ".", generateFail));
                continue;
            }
            Test generateSuccess = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Generate keypair.", generate);
            ECPrivateKey ecpriv = (ECPrivateKey) kp.getPrivate();

            //Perform KeyAgreement tests
            List<Test> allKaTests = new LinkedList<>();
            for (KeyAgreementIdent kaIdent : cfg.selected.getKAs()) {
                if (kaAlgo == null || kaIdent.containsAny(kaTypes)) {
                    List<Test> specificKaTests = new LinkedList<>();
                    for (EC_Key.Public pub : curveKeys.getValue()) {
                        ECPublicKey ecpub = ECUtil.toPublicKey(pub);
                        KeyAgreement ka = kaIdent.getInstance(cfg.selected.getProvider());
                        KeyAgreementTestable testable = new KeyAgreementTestable(ka, ecpriv ,ecpub);
                        Test keyAgreement = KeyAgreementTest.expectError(testable, Result.ExpectedValue.FAILURE);
                        specificKaTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Composite test of " + curve.getId() + ", with generated private key, " + pub.getDesc(), keyAgreement));
                    }
                    allKaTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Perform " + kaIdent.getName() + " with various public points.", specificKaTests.toArray(new Test[0])));
                }
            }
            if(allKaTests.isEmpty()) {
                allKaTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "None of the specified key agreement types is supported by the library."));
            }
            Test tests = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Do tests.", allKaTests.toArray(new Test[0]));
            doTest(CompoundTest.greedyAllTry(Result.ExpectedValue.SUCCESS, "Composite test of " + curve.getId() + ".", generateSuccess, tests));
        }


        Map<String, EC_Curve> results = EC_Store.getInstance().getObjects(EC_Curve.class, "composite");
        Map<String, List<EC_Curve>> groups = EC_Store.mapToPrefix(results.values());
        /* Test the whole curves with both keypairs generated by the library(no small-order public points provided).
         */
        List<EC_Curve> wholeCurves = groups.entrySet().stream().filter((e) -> e.getKey().equals("whole")).findFirst().get().getValue();
        testGroup(wholeCurves, kpg, "Composite generator order", Result.ExpectedValue.FAILURE);

        /* Also test having a G of small order, so small R.
         */
        List<EC_Curve> smallRCurves = groups.entrySet().stream().filter((e) -> e.getKey().equals("small")).findFirst().get().getValue();
        testGroup(smallRCurves, kpg, "Small generator order", Result.ExpectedValue.FAILURE);

        /* Test increasingly larger prime R, to determine where/if the behavior changes.
         */
        List<EC_Curve> varyingCurves = groups.entrySet().stream().filter((e) -> e.getKey().equals("varying")).findFirst().get().getValue();
        testGroup(varyingCurves, kpg, null, Result.ExpectedValue.ANY);

        /* Also test having a G of large but composite order, R = p * q,
         */
        List<EC_Curve> pqCurves = groups.entrySet().stream().filter((e) -> e.getKey().equals("pq")).findFirst().get().getValue();
        testGroup(pqCurves, kpg, null, Result.ExpectedValue.ANY);

        /* Also test having G or large order being a Carmichael pseudoprime, R = p * q * r,
         */
        List<EC_Curve> ppCurves = groups.entrySet().stream().filter((e) -> e.getKey().equals("pp")).findFirst().get().getValue();
        testGroup(ppCurves, kpg, "Generator order = Carmichael pseudo-prime", Result.ExpectedValue.ANY);

        /* Also test rg0 curves.
         */
        List<EC_Curve> rg0Curves = groups.entrySet().stream().filter((e) -> e.getKey().equals("rg0")).findFirst().get().getValue();
        testGroup(rg0Curves, kpg, null, Result.ExpectedValue.ANY);
    }

    private void testGroup(List<EC_Curve> curves, KeyPairGenerator kpg, String testName, Result.ExpectedValue dhValue) throws Exception {
         for (EC_Curve curve : curves) {
            String description;
            if (testName == null) {
                description = curve.getDesc() + " test of " + curve.getId() + ".";
            } else {
                description = testName + " test of " + curve.getId() + ".";
            }

            //generate KeyPair
             KeyGeneratorTestable kgt = new KeyGeneratorTestable(kpg, curve.toSpec());
             Test generate =  KeyGeneratorTest.expectError(kgt, Result.ExpectedValue.ANY);
             runTest(generate);
             KeyPair kp = kgt.getKeyPair();
             if(kp == null) {
                 Test generateFail = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Generating KeyPair has failed on " + curve.getId() +
                         ". " + " Other tests will be skipped.", generate);
                 doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, description, generateFail));
                 continue;
             }
             Test generateSuccess = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Generate keypair.", generate);
             ECPrivateKey ecpriv = (ECPrivateKey) kp.getPrivate();
             ECPublicKey ecpub = (ECPublicKey) kp.getPublic();

            //perform KeyAgreement tests
            List<Test> kaTests = new LinkedList<>();
            for (KeyAgreementIdent kaIdent : cfg.selected.getKAs()) {
                if (kaAlgo == null || kaIdent.containsAny(kaTypes)) {
                    KeyAgreement ka = kaIdent.getInstance(cfg.selected.getProvider());
                    KeyAgreementTestable testable = new KeyAgreementTestable(ka, ecpriv, ecpub);
                    kaTests.add(KeyAgreementTest.expectError(testable, dhValue));
                }
            }
            if(kaTests.isEmpty()) {
                kaTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "None of the specified KeyAgreement types is supported by the library."));
            }

            //perform Signature tests
            List<Test> sigTests = new LinkedList<>();
            for (SignatureIdent sigIdent : cfg.selected.getSigs()) {
                if (sigAlgo == null || sigIdent.containsAny(sigTypes)) {
                    Signature sig = sigIdent.getInstance(cfg.selected.getProvider());
                    SignatureTestable testable = new SignatureTestable(sig, ecpriv, ecpub, null);
                    sigTests.add(SignatureTest.expectError(testable, dhValue));
                }
            }
            if(sigTests.isEmpty()) {
                sigTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "None of the specified Signature types is supported by the library."));
            }

            Test performKeyAgreements = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Perform specified KeyAgreements.", kaTests.toArray(new Test[0]));
            Test performSignatures = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Perform specified Signatures.", sigTests.toArray(new Test[0]));
            doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, description, generateSuccess, performKeyAgreements, performSignatures));
        }
    }
}
