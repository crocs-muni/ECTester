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
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author David Hofman
 */
public class StandalonePerformanceSuite extends StandaloneTestSuite {
    private final int count = 100;

    public StandalonePerformanceSuite(TestWriter writer, ECTesterStandalone.Config cfg, TreeCommandLine cli) {
        super(writer, cfg, cli, "performance", "The performance test suite measures performance of KeyPair generation, KeyAgreement and Signature operations.",
                "Supports options:",
                "\t - gt/kpg-type (select multiple types by separating them with commas)",
                "\t - kt/ka-type (select multiple types by separating them with commas)",
                "\t - st/sig-type (select multiple types by separating them with commas)",
                "\t - key-type");
    }

    @Override
    protected void runTests() throws Exception {
        String kpgAlgo = cli.getOptionValue("test.kpg-type");
        String kaAlgo = cli.getOptionValue("test.ka-type");
        String sigAlgo = cli.getOptionValue("test.sig-type");
        String keyAlgo = cli.getOptionValue("test.key-type", "AES");

        List<String> kpgTypes = kpgAlgo != null ? Arrays.asList(kpgAlgo.split(",")) : new ArrayList<>();
        List<String> kaTypes = kaAlgo != null ? Arrays.asList(kaAlgo.split(",")) : new ArrayList<>();
        List<String> sigTypes = sigAlgo != null ? Arrays.asList(sigAlgo.split(",")) : new ArrayList<>();

        List<KeyPairGeneratorIdent> kpgIdents = new LinkedList<>();
        if (kpgAlgo == null) {
            // try EC, if not, fail with: need to specify kpg algo.
            Optional<KeyPairGeneratorIdent> kpgIdentOpt = cfg.selected.getKPGs().stream()
                    .filter((ident) -> ident.contains("EC"))
                    .findFirst();
            if (kpgIdentOpt.isPresent()) {
                kpgIdents.add(kpgIdentOpt.get());
            } else {
                System.err.println("The default KeyPairGenerator algorithm type of \"EC\" was not found. Need to specify a type.");
                return;
            }
        } else {
            // try the specified, if not, fail with: wrong kpg algo/not found.
            kpgIdents = cfg.selected.getKPGs().stream()
                    .filter((ident) -> ident.containsAny(kpgTypes)).collect(Collectors.toList());
            if (kpgIdents.isEmpty()) {
                System.err.println("No KeyPairGenerator algorithms of specified types were found.");
                return;
            }
        }

        KeyGeneratorTestable kgtOne = null;
        KeyGeneratorTestable kgtOther = null;
        ECParameterSpec spec = null;
        List<Test> kpgTests = new LinkedList<>();
        for(KeyPairGeneratorIdent kpgIdent : kpgIdents) {
            KeyPairGenerator kpg = kpgIdent.getInstance(cfg.selected.getProvider());
            if (cli.hasOption("test.bits")) {
                int bits = Integer.parseInt(cli.getOptionValue("test.bits"));
                kgtOne = new KeyGeneratorTestable(kpg, bits);
                kgtOther = new KeyGeneratorTestable(kpg, bits);
            } else if (cli.hasOption("test.named-curve")) {
                String curveName = cli.getOptionValue("test.named-curve");
                EC_Curve curve = EC_Store.getInstance().getObject(EC_Curve.class, curveName);
                if (curve == null) {
                    System.err.println("Curve not found: " + curveName);
                    return;
                }
                spec = curve.toSpec();
                kgtOne = new KeyGeneratorTestable(kpg, spec);
                kgtOther = new KeyGeneratorTestable(kpg, spec);
            } else {
                kgtOne = new KeyGeneratorTestable(kpg);
                kgtOther = new KeyGeneratorTestable(kpg);
            }
            kpgTests.add(PerformanceTest.repeat(kgtOne, kpgIdent.getName(), count));
        }
        runTest(KeyGeneratorTest.expect(kgtOther, Result.ExpectedValue.SUCCESS));
        doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "KeyPairGenerator performance tests", kpgTests.toArray(new Test[0])));

        List<Test> kaTests = new LinkedList<>();
        for (KeyAgreementIdent kaIdent : cfg.selected.getKAs()) {
            if (kaAlgo == null || kaIdent.containsAny(kaTypes)) {
                KeyAgreement ka = kaIdent.getInstance(cfg.selected.getProvider());
                KeyAgreementTestable testable;
                if (kaIdent.requiresKeyAlgo()) {
                    testable = new KeyAgreementTestable(ka, kgtOne, kgtOther, spec, keyAlgo);
                } else {
                    testable = new KeyAgreementTestable(ka, kgtOne, kgtOther, spec);
                }
                kaTests.add(PerformanceTest.repeat(testable, kaIdent.getName(), count));
            }
        }
        if(kaTests.isEmpty()) {
            kaTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "None of the specified KeyAgreement types is supported by the library."));
        }
        doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "KeyAgreement performance tests", kaTests.toArray(new Test[0])));

        List<Test> sigTests = new LinkedList<>();
        List<Test> sigTestsNoVerification = new LinkedList<>();
        for (SignatureIdent sigIdent : cfg.selected.getSigs()) {
            if (sigAlgo == null || sigIdent.containsAny(sigTypes)) {
                Signature sig = sigIdent.getInstance(cfg.selected.getProvider());
                sigTests.add(PerformanceTest.repeat(new SignatureTestable(sig, kgtOne, null), sigIdent.getName(),count));
                if(kgtOne.getKeyPair() != null) {
                    ECPrivateKey signKey = (ECPrivateKey) kgtOne.getKeyPair().getPrivate();
                    sigTestsNoVerification.add(PerformanceTest.repeat(new SignatureTestable(sig, signKey, null, null), sigIdent.getName(), count));
                }
            }
        }
        if(sigTestsNoVerification.isEmpty() & !sigTests.isEmpty()) {
            sigTestsNoVerification.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Signature tests with no verification require a successfully generated private key."));
        }
        if(sigTests.isEmpty()) {
            sigTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "None of the specified Signature types is supported by the library."));
            sigTestsNoVerification.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "None of the specified Signature types is supported by the library."));
        }
        Test signAndVerify = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Sign and verify", sigTests.toArray(new Test[0]));
        Test signOnly = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Sign only, no verification", sigTestsNoVerification.toArray(new Test[0]));
        doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Signature performance tests", signAndVerify, signOnly));
    }
}
