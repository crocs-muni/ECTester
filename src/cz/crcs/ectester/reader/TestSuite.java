package cz.crcs.ectester.reader;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.ec.*;

import javax.smartcardio.CardException;
import java.io.IOException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class TestSuite {

    EC_Store dataStore;
    ECTester.Config cfg;
    String name;
    boolean hasRun;
    List<Test> tests = new LinkedList<>();

    public TestSuite(EC_Store dataStore, ECTester.Config cfg, String name) {
        this.dataStore = dataStore;
        this.cfg = cfg;
        this.name = name;
    }

    public List<Test> run(CardMngr cardManager) throws IOException, CardException {
        for (Test t : tests) {
            t.run();
            System.out.println(t);
        }
        hasRun = true;
        return tests;
    }

    public List<Test> getTests() {
        return Collections.unmodifiableList(tests);
    }

    public boolean hasRun() {
        return hasRun;
    }

    public String getName() {
        return name;
    }

    public static class Default extends TestSuite {

        public Default(EC_Store dataStore, ECTester.Config cfg) {
            super(dataStore, cfg, "default");
        }

        @Override
        public List<Test> run(CardMngr cardManager) {
            return null;
        }
    }

    public static class TestVectors extends TestSuite {

        public TestVectors(EC_Store dataStore, ECTester.Config cfg) {
            super(dataStore, cfg, "test");
        }

        @Override
        public List<Test> run(CardMngr cardManager) throws IOException, CardException {

            Map<String, EC_KAResult> results = dataStore.getObjects(EC_KAResult.class, "test");
            for (EC_KAResult result : results.values()) {
                EC_Curve curve = dataStore.getObject(EC_Curve.class, result.getCurve());
                if (cfg.namedCurve != null && !(result.getCurve().startsWith(cfg.namedCurve) || result.getCurve().equals(cfg.namedCurve))) {
                    continue;
                }
                if (curve.getBits() != cfg.bits && !cfg.all) {
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
            Map<String, EC_Key> keys = dataStore.getObjects(EC_Key.class, "nonprime");
            for (EC_Key key : keys.values()) {
                EC_Curve curve = dataStore.getObject(EC_Curve.class, key.getCurve());
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
        public List<Test> run(CardMngr cardManager) throws IOException, CardException {
            Map<String, EC_Key.Public> pubkeys = dataStore.getObjects(EC_Key.Public.class, "invalid");
            for (EC_Key.Public key : pubkeys.values()) {
                EC_Curve curve = dataStore.getObject(EC_Curve.class, key.getCurve());
                if (cfg.namedCurve != null && !(key.getCurve().startsWith(cfg.namedCurve) || key.getCurve().equals(cfg.namedCurve))) {
                    continue;
                }
                if (curve.getBits() != cfg.bits && !cfg.all) {
                    continue;
                }
                tests.add(new Test(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), curve.getField()), Test.Result.SUCCESS));
                tests.add(new Test(new Command.Set(cardManager, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), Test.Result.SUCCESS));
                tests.add(new Test(new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_LOCAL), Test.Result.SUCCESS));
                tests.add(new Test(new Command.Set(cardManager, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, key.getParams(), key.flatten()), Test.Result.ANY));
                tests.add(new Test(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_NONE, EC_Consts.KA_BOTH), Test.Result.FAILURE));
                tests.add(new Test(new Command.Cleanup(cardManager), Test.Result.ANY));
            }
            return super.run(cardManager);
        }
    }
}
