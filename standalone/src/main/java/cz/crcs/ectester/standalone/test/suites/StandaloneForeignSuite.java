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
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.*;

public abstract class StandaloneForeignSuite extends StandaloneTestSuite {
    private String capName;

    public StandaloneForeignSuite(TestWriter writer, ECTesterStandalone.Config cfg, TreeCommandLine cli, String name, String... description) {
        super(writer, cfg, cli, name, description);
        this.capName = name.substring(0, 1).toUpperCase() + name.substring(1);
    }

    @Override
    protected void runTests() throws Exception {
        String kpgAlgo = cli.getOptionValue("test.kpg-type");
        String kaAlgo = cli.getOptionValue("test.ka-type");

        List<String> kaTypes = kaAlgo != null ? Arrays.asList(kaAlgo.split(",")) : new ArrayList<>();

        KeyPairGeneratorIdent kpgIdent = getKeyPairGeneratorIdent(kpgAlgo);
        if (kpgIdent == null) {
            return;
        }

        Map<String, EC_Key.Public> pubkeys = EC_Store.getInstance().getObjects(EC_Key.Public.class, this.name);
        Map<EC_Curve, List<EC_Key.Public>> curveList = EC_Store.mapKeyToCurve(pubkeys.values());
        for (Map.Entry<EC_Curve, List<EC_Key.Public>> e : curveList.entrySet()) {
            EC_Curve curve = e.getKey();
            List<EC_Key.Public> keys = e.getValue();
            ECPublicKey singlePkey = ECUtil.toPublicKey(keys.get(0));

            KeyPairGenerator kpg = kpgIdent.getInstance(cfg.selected.getProvider());
            ECParameterSpec spec = curve.toSpec();
            ECGenParameterSpec namedSpec = new ECGenParameterSpec(curve.getId());

            KeyGeneratorTestable kgt = KeyGeneratorTestable.builder().keyPairGenerator(kpg).random(getRandom()).spec(spec).build();
            KeyGeneratorTestable kgtOnNamedCurve = KeyGeneratorTestable.builder().keyPairGenerator(kpg).random(getRandom()).spec(namedSpec).build();
            KeyGeneratorTestable kgtOnDefaultCurve = KeyGeneratorTestable.builder().keyPairGenerator(kpg).random(getRandom()).keysize(curve.getBits()).build();

            // This is some nasty hacking...
            KeyGeneratorTestable theKgt = new KeyGeneratorTestable(kpg) {
                private KeyGeneratorTestable current = null;

                @Override
                public Exception getException() {
                    if (current != null) {
                        return current.getException();
                    }
                    return super.getException();
                }

                @Override
                public KeyGeneratorStage getStage() {
                    if (current != null) {
                        return current.getStage();
                    }
                    return super.getStage();
                }

                @Override
                public void run() {
                    stage = KeyGeneratorStage.Init;
                    kgt.run();
                    if (kgt.ok()) {
                        ok = true;
                        error = false;
                        current = kgt;
                        hasRun = true;
                        return;
                    }
                    kgtOnNamedCurve.run();
                    if (kgtOnNamedCurve.ok()) {
                        ok = true;
                        error = false;
                        current = kgtOnNamedCurve;
                        hasRun = true;
                        return;
                    }
                    kgtOnDefaultCurve.run();
                    if (kgtOnDefaultCurve.ok() && ECUtil.equalKeyPairParameters((ECPrivateKey) kgtOnDefaultCurve.getKeyPair().getPrivate(), singlePkey)) {
                        ok = true;
                        error = false;
                        current = kgtOnDefaultCurve;
                        hasRun = true;
                    }
                }

                @Override
                public KeyPair getKeyPair() {
                    if (current != null) {
                        return current.getKeyPair();
                    }
                    return super.getKeyPair();
                }

                @Override
                public KeyPairGenerator getKpg() {
                    if (current != null) {
                        return current.getKpg();
                    }
                    return super.getKpg();
                }

                @Override
                public AlgorithmParameterSpec getSpec() {
                    if (current != null) {
                        return current.getSpec();
                    }
                    return super.getSpec();
                }

                @Override
                public int getKeysize() {
                    if (current != null) {
                        return current.getKeysize();
                    }
                    return super.getKeysize();
                }
            };

            Test generate = KeyGeneratorTest.expectError(kgt, Result.ExpectedValue.SUCCESS);
            Test generateOnNamedCurve = KeyGeneratorTest.expectError(kgtOnNamedCurve, Result.ExpectedValue.SUCCESS);
            Test generateOnDefaultCurve = KeyGeneratorTest.expectError(kgtOnDefaultCurve, Result.ExpectedValue.SUCCESS);
            Test generateFinal = KeyGeneratorTest.expectError(theKgt, Result.ExpectedValue.SUCCESS);
            //generate, generateOnNamedCurve, generateOnDefaultCurve,
            Test generateAny = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Generate a keypair on the standard curve.",  generateFinal);

            List<Test> allKaTests = new LinkedList<>();
            for (KeyAgreementIdent kaIdent : cfg.selected.getKAs()) {
                if (kaAlgo == null || kaIdent.containsAny(kaTypes)) {
                    List<Test> specificKaTests = new LinkedList<>();
                    for (EC_Key.Public pub : keys) {
                        ECPublicKey ecpub = ECUtil.toPublicKey(pub);
                        KeyAgreement ka = kaIdent.getInstance(cfg.selected.getProvider());
                        KeyAgreementTestable testable = KeyAgreementTestable.builder().ka(ka).publicKey(ecpub).privateKgt(theKgt).random(getRandom()).build();
                        Test keyAgreement = KeyAgreementTest.expectError(testable, Result.ExpectedValue.FAILURE);
                        specificKaTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, pub.getId() + " invalid key test.", keyAgreement));
                    }
                    for (int i = 0; i < getNumRepeats(); i++) {
                        allKaTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "Perform " + kaIdent.getName() + " with invalid public points.", specificKaTests.toArray(new Test[0])));
                    }
                }
            }
            if (cli.hasOption("test.shuffle")) {
                Collections.shuffle(allKaTests);
            }
            if (allKaTests.isEmpty()) {
                allKaTests.add(CompoundTest.all(Result.ExpectedValue.SUCCESS, "None of the specified key agreement types is supported by the library."));
            }
            Test tests = CompoundTest.all(Result.ExpectedValue.SUCCESS, "Do tests.", allKaTests.toArray(new Test[0]));
            doTest(CompoundTest.greedyAllTry(Result.ExpectedValue.SUCCESS, this.capName + " curve test of " + curve.getId() + ".", generateAny, tests));
        }
    }
}
