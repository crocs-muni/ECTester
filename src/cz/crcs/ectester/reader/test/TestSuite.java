package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTester;
import cz.crcs.ectester.reader.command.Command;
import cz.crcs.ectester.reader.ec.*;

import java.io.IOException;
import java.util.*;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class TestSuite {
    EC_Store dataStore;
    ECTester.Config cfg;
    String name;
    String description;
    List<Test> tests = new LinkedList<>();

    TestSuite(EC_Store dataStore, ECTester.Config cfg, String name, String description) {
        this.dataStore = dataStore;
        this.cfg = cfg;
        this.name = name;
        this.description = description;
    }

    public abstract void setup(CardMngr cardManager) throws IOException;

    public List<Test> getTests() {
        return Collections.unmodifiableList(tests);
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    /**
     * @param cardManager      cardManager to send APDU through
     * @param generateExpected expected result of the Generate command
     * @param ecdhExpected     expected result of the ordinary ECDH command
     * @param ecdsaExpected    expected result of the ordinary ECDSA command
     * @return tests to run
     */
    List<Test> defaultCurveTests(CardMngr cardManager, Result.Value generateExpected, Result.Value ecdhExpected, Result.Value ecdsaExpected) {
        List<Test> tests = new LinkedList<>();

        tests.add(new Test.Simple(new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_BOTH), generateExpected));
        tests.add(new Test.Simple(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_NONE, EC_Consts.KA_ECDH), ecdhExpected));
        tests.add(new Test.Simple(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_COMPRESS, EC_Consts.KA_ECDH), ecdhExpected));
        tests.add(new Test.Simple(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_ONE, EC_Consts.KA_ECDH), Result.Value.FAILURE));
        tests.add(new Test.Simple(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_ZERO, EC_Consts.KA_ECDH), Result.Value.FAILURE));
        tests.add(new Test.Simple(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_MAX, EC_Consts.KA_ECDH), Result.Value.FAILURE));
        tests.add(new Test.Simple(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_FULLRANDOM, EC_Consts.KA_ECDH), Result.Value.FAILURE));
        tests.add(new Test.Simple(new Command.ECDSA(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, null), ecdsaExpected));

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
    List<Test> defaultCategoryTests(CardMngr cardManager, String category, byte field, Result.Value setExpected, Result.Value generateExpected, Result.Value ecdhExpected, Result.Value ecdsaExpected) {
        List<Test> tests = new LinkedList<>();
        Map<String, EC_Curve> curves = dataStore.getObjects(EC_Curve.class, category);
        if (curves == null)
            return tests;
        for (Map.Entry<String, EC_Curve> entry : curves.entrySet()) {
            EC_Curve curve = entry.getValue();
            if (curve.getField() == field && (curve.getBits() == cfg.bits || cfg.all)) {
                tests.add(new Test.Simple(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), field), Result.Value.SUCCESS));
                tests.add(new Test.Simple(new Command.Set(cardManager, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), setExpected));
                tests.addAll(defaultCurveTests(cardManager, generateExpected, ecdhExpected, ecdsaExpected));
                tests.add(new Test.Simple(new Command.Cleanup(cardManager), Result.Value.ANY));
            }
        }

        return tests;
    }
}
