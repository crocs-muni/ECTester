package cz.crcs.ectester.standalone.test.suites;

import cz.crcs.ectester.common.cli.TreeCommandLine;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.standalone.ECTesterStandalone;
import cz.crcs.ectester.standalone.consts.KeyAgreementIdent;
import cz.crcs.ectester.standalone.consts.KeyPairGeneratorIdent;
import cz.crcs.ectester.standalone.consts.SignatureIdent;
import cz.crcs.ectester.standalone.test.base.*;

import javax.crypto.KeyAgreement;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.*;

/**
 * @author David Hofman
 */
public class StandaloneMiscSuite extends StandaloneTestSuite {
    private String kpgAlgo;
    private String kaAlgo;
    private String sigAlgo;
    private List<String> kaTypes;
    private List<String> sigTypes;

    public StandaloneMiscSuite(TestWriter writer, ECTesterStandalone.Config cfg, TreeCommandLine cli) {
        super(writer, cfg, cli, "miscellaneous", "Some miscellaneous tests, tries ECDH and ECDSA over supersingular curves, anomalous curves,",
                "Barreto-Naehrig curves with small embedding degree and CM discriminant, MNT curves,",
                "some Montgomery curves transformed to short Weierstrass form and Curve25519 transformed to short Weierstrass form.",
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

        Map<String, EC_Curve> anCurves = EC_Store.getInstance().getObjects(EC_Curve.class, "anomalous");
        Map<String, EC_Curve> ssCurves = EC_Store.getInstance().getObjects(EC_Curve.class, "supersingular");
        Map<String, EC_Curve> bnCurves = EC_Store.getInstance().getObjects(EC_Curve.class, "Barreto-Naehrig");
        Map<String, EC_Curve> mntCurves = EC_Store.getInstance().getObjects(EC_Curve.class, "MNT");
        List<EC_Curve> mCurves = new ArrayList<>();
        mCurves.add(EC_Store.getInstance().getObject(EC_Curve.class, "other", "M-221"));
        mCurves.add(EC_Store.getInstance().getObject(EC_Curve.class, "other", "M-383"));
        mCurves.add(EC_Store.getInstance().getObject(EC_Curve.class, "other", "M-511"));
        EC_Curve curve25519 = EC_Store.getInstance().getObject(EC_Curve.class, "other", "Curve25519");

        testCurves(anCurves.values(), "anomalous", kpg, Result.ExpectedValue.FAILURE);
        testCurves(ssCurves.values(), "supersingular", kpg, Result.ExpectedValue.FAILURE);
        testCurves(bnCurves.values(), "Barreto-Naehrig", kpg, Result.ExpectedValue.SUCCESS);
        testCurves(mntCurves.values(), "MNT", kpg, Result.ExpectedValue.SUCCESS);
        testCurves(mCurves, "Montgomery", kpg, Result.ExpectedValue.SUCCESS);
        testCurve(curve25519, "Montgomery", kpg, Result.ExpectedValue.SUCCESS);
    }

    private void testCurve(EC_Curve curve, String catName, KeyPairGenerator kpg, Result.ExpectedValue expected) throws NoSuchAlgorithmException {
        //generate KeyPair
        KeyGeneratorTestable kgt = new KeyGeneratorTestable(kpg, curve.toSpec());
        Test generate =  KeyGeneratorTest.expectError(kgt, Result.ExpectedValue.ANY);
        runTest(generate);
        KeyPair kp = kgt.getKeyPair();
        if(kp == null) {
            Test generateFail = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Generating KeyPair has failed on " + curve.getId() +
                    ". " + " Other tests will be skipped.", generate);
            doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Tests over " + curve.getBits() + "b " + catName + " curve: " + curve.getId() + ".", generateFail));
            return;
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
                kaTests.add(KeyAgreementTest.expectError(testable, expected));
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
                sigTests.add(SignatureTest.expectError(testable, expected));
            }
        }
        if(sigTests.isEmpty()) {
            sigTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "None of the specified Signature types is supported by the library."));
        }

        Test performKeyAgreements = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Perform specified KeyAgreements.", kaTests.toArray(new Test[0]));
        Test performSignatures = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Perform specified Signatures.", sigTests.toArray(new Test[0]));
        doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Tests over " + curve.getBits() + "b " + catName + " curve: " + curve.getId() + ".", generateSuccess, performKeyAgreements, performSignatures));
    }

    private void testCurves(Collection<EC_Curve> curves, String catName, KeyPairGenerator kpg, Result.ExpectedValue expected) throws NoSuchAlgorithmException {
        for (EC_Curve curve : curves) {
            testCurve(curve, catName, kpg, expected);
        }
    }
}
