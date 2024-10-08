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
        String kpgAlgo = cli.getOptionValue("test.kpg-type", "EC");
        String kaAlgo = cli.getOptionValue("test.ka-type", "ECDH");
        String sigAlgo = cli.getOptionValue("test.sig-type", "ECDSA");
        String keyAlgo = cli.getOptionValue("test.key-type", "AES");

        List<String> kpgTypes = kpgAlgo != null ? Arrays.asList(kpgAlgo.split(",")) : new ArrayList<>();
        List<String> kaTypes = kaAlgo != null ? Arrays.asList(kaAlgo.split(",")) : new ArrayList<>();
        List<String> sigTypes = sigAlgo != null ? Arrays.asList(sigAlgo.split(",")) : new ArrayList<>();

        List<KeyPairGeneratorIdent> kpgIdents = new LinkedList<>();
        for (String kpgChoice : kpgTypes) {
            KeyPairGeneratorIdent ident = getKeyPairGeneratorIdent(kpgChoice);
            if (ident != null && !kpgIdents.contains(ident)) {
                kpgIdents.add(ident);
            }
        }
        if (kpgIdents.isEmpty()) {
            System.err.println("Need some KeyPairGenerators to be able to generate keys. Select at least one supported one using the -gt/--kpg-type option.");
            return;
        }

        KeyGeneratorTestable kgtOne = null;
        KeyGeneratorTestable kgtOther = null;
        ECParameterSpec spec = null;
        List<Test> kpgTests = new LinkedList<>();
        for (KeyPairGeneratorIdent kpgIdent : kpgIdents) {
            KeyPairGenerator kpg = kpgIdent.getInstance(cfg.selected.getProvider());
            if (cli.hasOption("test.bits")) {
                int bits = Integer.parseInt(cli.getOptionValue("test.bits"));
                kgtOne = KeyGeneratorTestable.builder().keyPairGenerator(kpg).keysize(bits).random(getRandom()).build();
                kgtOther = KeyGeneratorTestable.builder().keyPairGenerator(kpg).keysize(bits).random(getRandom()).build();
            } else if (cli.hasOption("test.named-curve")) {
                String curveName = cli.getOptionValue("test.named-curve");
                EC_Curve curve = EC_Store.getInstance().getObject(EC_Curve.class, curveName);
                if (curve == null) {
                    System.err.println("Curve not found: " + curveName);
                    return;
                }
                spec = curve.toSpec();
                kgtOne = KeyGeneratorTestable.builder().keyPairGenerator(kpg).spec(spec).random(getRandom()).build();
                kgtOther = KeyGeneratorTestable.builder().keyPairGenerator(kpg).spec(spec).random(getRandom()).build();
            } else {
                kgtOne = KeyGeneratorTestable.builder().keyPairGenerator(kpg).random(getRandom()).build();
                kgtOther = KeyGeneratorTestable.builder().keyPairGenerator(kpg).random(getRandom()).build();
            }
            kpgTests.add(PerformanceTest.repeat(kgtOne, cfg.selected, kpgIdent.getName(), count));
            kpgTests.add(PerformanceTest.repeat(kgtOther, cfg.selected, kpgIdent.getName(), count));
        }
        doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "KeyPairGenerator performance tests", kpgTests.toArray(new Test[0])));

        List<Test> kaTests = new LinkedList<>();
        for (KeyAgreementIdent kaIdent : cfg.selected.getKAs()) {
            if (kaAlgo == null || kaIdent.containsAny(kaTypes)) {
                KeyAgreement ka = kaIdent.getInstance(cfg.selected.getProvider());
                KeyAgreementTestable testable;
                if (kaIdent.requiresKeyAlgo()) {
                    testable = KeyAgreementTestable.builder().ka(ka).privateKgt(kgtOne).publicKgt(kgtOther).spec(spec).random(getRandom()).keyAlgo(keyAlgo).build();
                } else {
                    testable = KeyAgreementTestable.builder().ka(ka).privateKgt(kgtOne).publicKgt(kgtOther).spec(spec).random(getRandom()).build();
                }
                kaTests.add(PerformanceTest.repeat(testable, cfg.selected, kaIdent.getName(), count));
            }
        }
        if (kaTests.isEmpty()) {
            kaTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "None of the specified KeyAgreement types is supported by the library."));
        }
        doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "KeyAgreement performance tests", kaTests.toArray(new Test[0])));

        List<Test> sigTests = new LinkedList<>();
        List<Test> sigTestsNoVerification = new LinkedList<>();
        for (SignatureIdent sigIdent : cfg.selected.getSigs()) {
            if (sigAlgo == null || sigIdent.containsAny(sigTypes)) {
                Signature sig = sigIdent.getInstance(cfg.selected.getProvider());
                byte[] data = sigIdent.toString().getBytes();
                sigTests.add(PerformanceTest.repeat(new SignatureTestable(sig, kgtOne, data, getRandom()), cfg.selected, sigIdent.getName(), count));
                // TODO: The following will always fail as a runTest is not done at this point.
                if (kgtOne.getKeyPair() != null) {
                    ECPrivateKey signKey = (ECPrivateKey) kgtOne.getKeyPair().getPrivate();
                    sigTestsNoVerification.add(PerformanceTest.repeat(new SignatureTestable(sig, signKey, null, data, getRandom()), cfg.selected, sigIdent.getName(), count));
                }
            }
        }
        if (sigTestsNoVerification.isEmpty() & !sigTests.isEmpty()) {
            sigTestsNoVerification.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Signature tests with no verification require a successfully generated private key."));
        }
        if (sigTests.isEmpty()) {
            sigTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "None of the specified Signature types is supported by the library."));
            sigTestsNoVerification.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "None of the specified Signature types is supported by the library."));
        }
        Test signAndVerify = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Sign and verify", sigTests.toArray(new Test[0]));
        Test signOnly = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Sign only, no verification", sigTestsNoVerification.toArray(new Test[0]));
        doTest(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Signature performance tests", signAndVerify, signOnly));
    }
}
