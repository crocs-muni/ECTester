package cz.crcs.ectester.reader;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.ec.*;
import javacard.security.Key;
import javacard.security.KeyPair;

import javax.smartcardio.CardException;
import java.io.IOException;
import java.util.*;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class TestSuite {

    EC_Store dataStore;
    ECTester.Config cfg;
    String name;
    List<Test> tests = new LinkedList<>();

    TestSuite(EC_Store dataStore, ECTester.Config cfg, String name) {
        this.dataStore = dataStore;
        this.cfg = cfg;
        this.name = name;
    }

    public List<Test> run(CardMngr cardManager) throws CardException, IOException {
        for (Test t : tests) {
            if (!t.hasRun()) {
                t.run();
                System.out.println(t);
            }
        }
        return tests;
    }

    public List<Test> getTests() {
        return Collections.unmodifiableList(tests);
    }

    public String getName() {
        return name;
    }

    /**
     * @param cardManager      cardManager to send APDU through
     * @param generateExpected expected result of the Generate command
     * @param ecdhExpected     expected result of the ordinary ECDH command
     * @param ecdsaExpected    expected result of the ordinary ECDSA command
     * @return tests to run
     */
    List<Test> testCurve(CardMngr cardManager, Test.Result generateExpected, Test.Result ecdhExpected, Test.Result ecdsaExpected) {
        List<Test> tests = new LinkedList<>();

        tests.add(new Test(new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_BOTH), generateExpected));
        tests.add(new Test(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_NONE, EC_Consts.KA_ECDH), ecdhExpected));
        tests.add(new Test(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_COMPRESS, EC_Consts.KA_ECDH), ecdhExpected));
        tests.add(new Test(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_ONE, EC_Consts.KA_ECDH), Test.Result.FAILURE));
        tests.add(new Test(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_ZERO, EC_Consts.KA_ECDH), Test.Result.FAILURE));
        tests.add(new Test(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_MAX, EC_Consts.KA_ECDH), Test.Result.FAILURE));
        tests.add(new Test(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_FULLRANDOM, EC_Consts.KA_ECDH), Test.Result.FAILURE));
        tests.add(new Test(new Command.ECDSA(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, null), ecdsaExpected));

        return tests;
    }

    /**
     * @param cardManager      cardManager to send APDU through
     * @param category         category to test
     * @param field            field to test (KeyPair.ALG_EC_FP || KeyPair.ALG_EC_F2M)
     * @param setExpected      expected result of the Set (curve) command
     * @param generateExpected expected result of the Generate command
     * @param ecdhExpected     expected result of the ordinary ECDH command
     * @param ecdsaExpected    expected result of the ordinary ECDSA command
     * @return tests to run
     */
    List<Test> testCategory(CardMngr cardManager, String category, byte field, Test.Result setExpected, Test.Result generateExpected, Test.Result ecdhExpected, Test.Result ecdsaExpected) {
        List<Test> tests = new LinkedList<>();
        Map<String, EC_Curve> curves = dataStore.getObjects(EC_Curve.class, category);
        if (curves == null)
            return tests;
        for (Map.Entry<String, EC_Curve> entry : curves.entrySet()) {
            EC_Curve curve = entry.getValue();
            if (curve.getField() == field && (curve.getBits() == cfg.bits || cfg.all)) {
                tests.add(new Test(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), field), Test.Result.SUCCESS));
                tests.add(new Test(new Command.Set(cardManager, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), setExpected));
                tests.addAll(testCurve(cardManager, generateExpected, ecdhExpected, ecdsaExpected));
                tests.add(new Test(new Command.Cleanup(cardManager), Test.Result.ANY));
            }
        }

        return tests;
    }

    public static class Default extends TestSuite {

        public Default(EC_Store dataStore, ECTester.Config cfg) {
            super(dataStore, cfg, "default");
        }

        @Override
        public List<Test> run(CardMngr cardManager) throws IOException, CardException {
            tests.add(new Test(new Command.Support(cardManager), Test.Result.ANY));
            if (cfg.namedCurve != null) {
                if (cfg.primeField) {
                    tests.addAll(testCategory(cardManager, cfg.namedCurve, KeyPair.ALG_EC_FP, Test.Result.SUCCESS, Test.Result.SUCCESS, Test.Result.SUCCESS, Test.Result.SUCCESS));
                }
                if (cfg.binaryField) {
                    tests.addAll(testCategory(cardManager, cfg.namedCurve, KeyPair.ALG_EC_F2M, Test.Result.SUCCESS, Test.Result.SUCCESS, Test.Result.SUCCESS, Test.Result.SUCCESS));
                }
            } else {
                if (cfg.all) {
                    if (cfg.primeField) {
                        //iterate over prime curve sizes used: EC_Consts.FP_SIZES
                        for (short keyLength : EC_Consts.FP_SIZES) {
                            defaultTests(cardManager, keyLength, KeyPair.ALG_EC_FP);
                        }
                    }
                    if (cfg.binaryField) {
                        //iterate over binary curve sizes used: EC_Consts.F2M_SIZES
                        for (short keyLength : EC_Consts.F2M_SIZES) {
                            defaultTests(cardManager, keyLength, KeyPair.ALG_EC_F2M);
                        }
                    }
                } else {
                    if (cfg.primeField) {
                        defaultTests(cardManager, (short) cfg.bits, KeyPair.ALG_EC_FP);
                    }

                    if (cfg.binaryField) {
                        defaultTests(cardManager, (short) cfg.bits, KeyPair.ALG_EC_F2M);
                    }
                }
            }
            return super.run(cardManager);
        }

        private void defaultTests(CardMngr cardManager, short keyLength, byte keyType) throws IOException {
            tests.add(new Test(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_BOTH, keyLength, keyType), Test.Result.SUCCESS));
            Command curve = Command.prepareCurve(cardManager, dataStore, cfg, ECTesterApplet.KEYPAIR_BOTH, keyLength, keyType);
            if (curve != null)
                tests.add(new Test(curve, Test.Result.SUCCESS));
            tests.addAll(testCurve(cardManager, Test.Result.SUCCESS, Test.Result.SUCCESS, Test.Result.SUCCESS));
            tests.add(new Test(new Command.Cleanup(cardManager), Test.Result.ANY));
        }
    }

    public static class TestVectors extends TestSuite {

        public TestVectors(EC_Store dataStore, ECTester.Config cfg) {
            super(dataStore, cfg, "test");
        }

        @Override
        public List<Test> run(CardMngr cardManager) throws IOException, CardException {
            /* Set original curves (secg/nist/brainpool). Set keypairs from test vectors.
             * Do ECDH both ways, export and verify that the result is correct.
             */
            Map<String, EC_KAResult> results = dataStore.getObjects(EC_KAResult.class, "test");
            for (EC_KAResult result : results.values()) {
                EC_Curve curve = dataStore.getObject(EC_Curve.class, result.getCurve());
                if (cfg.namedCurve != null && !(result.getCurve().startsWith(cfg.namedCurve) || result.getCurve().equals(cfg.namedCurve))) {
                    continue;
                }
                if (curve.getBits() != cfg.bits && !cfg.all) {
                    continue;
                }
                if (curve.getField() == KeyPair.ALG_EC_FP && !cfg.primeField || curve.getField() == KeyPair.ALG_EC_F2M && !cfg.binaryField) {
                    continue;
                }
                EC_Params onekey = dataStore.getObject(EC_Keypair.class, result.getOneKey());
                if (onekey == null) {
                    onekey = dataStore.getObject(EC_Key.Private.class, result.getOneKey());
                }
                EC_Params otherkey = dataStore.getObject(EC_Keypair.class, result.getOtherKey());
                if (otherkey == null) {
                    otherkey = dataStore.getObject(EC_Key.Public.class, result.getOtherKey());
                }
                if (onekey == null || otherkey == null) {
                    throw new IOException("Test vector keys couldn't be located.");
                }

                tests.add(new Test(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), curve.getField()), Test.Result.SUCCESS));
                tests.add(new Test(new Command.Set(cardManager, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), Test.Result.SUCCESS));
                //tests.add(new Test(new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_BOTH), Test.Result.SUCCESS));
                tests.add(new Test(new Command.Set(cardManager, ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.CURVE_external, EC_Consts.PARAMETER_S, onekey.flatten(EC_Consts.PARAMETER_S)), Test.Result.SUCCESS));
                tests.add(new Test(new Command.Set(cardManager, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, EC_Consts.PARAMETER_W, otherkey.flatten(EC_Consts.PARAMETER_W)), Test.Result.SUCCESS));
                tests.add(new Test(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_TRUE, EC_Consts.CORRUPTION_NONE, result.getKA()), Test.Result.SUCCESS, (command, response) -> {
                    Response.ECDH dh = (Response.ECDH) response;
                    if (!dh.successful() || !dh.hasSecret())
                        return Test.Result.FAILURE;
                    if (!Util.compareBytes(dh.getSecret(), 0, result.getParam(0), 0, dh.secretLength())) {
                        return Test.Result.FAILURE;
                    }
                    return Test.Result.SUCCESS;
                }));
                tests.add(new Test(new Command.Cleanup(cardManager), Test.Result.ANY));

            }
            return super.run(cardManager);
        }
    }

    public static class NonPrime extends TestSuite {

        public NonPrime(EC_Store dataStore, ECTester.Config cfg) {
            super(dataStore, cfg, "nonprime");
        }

        @Override
        public List<Test> run(CardMngr cardManager) throws IOException, CardException {
            /* Do the default tests with the public keys set to provided smallorder keys
             * over non-prime order curves. Essentially small subgroup attacks.
             * These should fail, the curves aren't safe so that if the computation with
             * a small order public key succeeds the private key modulo the public key order
             * is revealed.
             */
            Map<String, EC_Key> keys = dataStore.getObjects(EC_Key.class, "nonprime");
            for (EC_Key key : keys.values()) {
                EC_Curve curve = dataStore.getObject(EC_Curve.class, key.getCurve());
                if (cfg.namedCurve != null && !(key.getCurve().startsWith(cfg.namedCurve) || key.getCurve().equals(cfg.namedCurve))) {
                    continue;
                }
                if (curve.getField() == KeyPair.ALG_EC_FP && !cfg.primeField || curve.getField() == KeyPair.ALG_EC_F2M && !cfg.binaryField) {
                    continue;
                }
                if ((curve.getBits() == cfg.bits || cfg.all)) {
                    tests.add(new Test(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), curve.getField()), Test.Result.SUCCESS));
                    tests.add(new Test(new Command.Set(cardManager, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), Test.Result.ANY));
                    tests.add(new Test(new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_LOCAL), Test.Result.ANY));
                    tests.add(new Test(new Command.Set(cardManager, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, key.getParams(), key.flatten()), Test.Result.ANY));
                    tests.add(new Test(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_NONE, EC_Consts.KA_ECDH), Test.Result.FAILURE));
                    tests.add(new Test(new Command.Cleanup(cardManager), Test.Result.ANY));
                }
            }
            return super.run(cardManager);
        }
    }

    public static class Invalid extends TestSuite {

        public Invalid(EC_Store dataStore, ECTester.Config cfg) {
            super(dataStore, cfg, "invalid");
        }

        @Override
        public List<Test> run(CardMngr cardManager) throws CardException, IOException {
            /* Set original curves (secg/nist/brainpool). Generate local.
             * Try ECDH with invalid public keys of increasing (or decreasing) order.
             */
            Map<String, EC_Key.Public> pubkeys = dataStore.getObjects(EC_Key.Public.class, "invalid");
            Map<EC_Curve, List<EC_Key.Public>> curves = new HashMap<>();
            for (EC_Key.Public key : pubkeys.values()) {
                EC_Curve curve = dataStore.getObject(EC_Curve.class, key.getCurve());
                if (cfg.namedCurve != null && !(key.getCurve().startsWith(cfg.namedCurve) || key.getCurve().equals(cfg.namedCurve))) {
                    continue;
                }
                if (curve.getBits() != cfg.bits && !cfg.all) {
                    continue;
                }
                if (curve.getField() == KeyPair.ALG_EC_FP && !cfg.primeField || curve.getField() == KeyPair.ALG_EC_F2M && !cfg.binaryField) {
                    continue;
                }
                List<EC_Key.Public> keys = curves.getOrDefault(curve, new LinkedList<>());
                keys.add(key);
                curves.putIfAbsent(curve, keys);
            }
            for (Map.Entry<EC_Curve, List<EC_Key.Public>> e : curves.entrySet()) {
                EC_Curve curve = e.getKey();
                List<EC_Key.Public> keys = e.getValue();

                tests.add(new Test(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), curve.getField()), Test.Result.SUCCESS));
                tests.add(new Test(new Command.Set(cardManager, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), Test.Result.SUCCESS));
                tests.add(new Test(new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_LOCAL), Test.Result.SUCCESS));
                for (EC_Key.Public pub : keys) {
                    tests.add(new Test(new Command.Set(cardManager, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, pub.getParams(), pub.flatten()), Test.Result.ANY));
                    tests.add(new Test(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_NONE, EC_Consts.KA_ANY), Test.Result.FAILURE));
                }
                tests.add(new Test(new Command.Cleanup(cardManager), Test.Result.ANY));
            }

            return super.run(cardManager);
        }
    }

    public static class Wrong extends TestSuite {

        public Wrong(EC_Store dataStore, ECTester.Config cfg) {
            super(dataStore, cfg, "wrong");
        }

        @Override
        public List<Test> run(CardMngr cardManager) throws CardException, IOException {
            /* Just do the default tests on the wrong curves.
             * These should generally fail, the curves aren't curves.
             */
            if (cfg.primeField) {
                tests.addAll(testCategory(cardManager, cfg.testSuite, KeyPair.ALG_EC_FP, Test.Result.FAILURE, Test.Result.FAILURE, Test.Result.FAILURE, Test.Result.FAILURE));
            }
            if (cfg.binaryField) {
                tests.addAll(testCategory(cardManager, cfg.testSuite, KeyPair.ALG_EC_F2M, Test.Result.FAILURE, Test.Result.FAILURE, Test.Result.FAILURE, Test.Result.FAILURE));
            }
            return super.run(cardManager);
        }
    }
}
