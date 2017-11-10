package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.CardMngr;
import cz.crcs.ectester.reader.ECTester;
import cz.crcs.ectester.reader.command.Command;
import cz.crcs.ectester.reader.ec.EC_Curve;

import java.io.IOException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static cz.crcs.ectester.reader.test.Result.ExpectedValue;
import static cz.crcs.ectester.reader.test.Result.Value;

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
     * @param cardManager          cardManager to send APDU through
     * @param generateExpected     expected result of the Generate command
     * @param ecdhExpected         expected result of the ordinary ECDH command
     * @param ecdhCompressExpected expected result of ECDH with a compressed point
     * @param ecdsaExpected        expected result of the ordinary ECDSA command
     * @param description          compound test description
     * @return test to run
     */
    Test defaultCurveTests(CardMngr cardManager, ExpectedValue generateExpected, ExpectedValue ecdhExpected, ExpectedValue ecdhCompressExpected, ExpectedValue ecdsaExpected, String description) {
        List<Test> tests = new LinkedList<>();

        tests.add(new Test.Simple(new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_BOTH), generateExpected));
        tests.add(new Test.Simple(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_NONE, EC_Consts.KA_ECDH), ecdhExpected));
        tests.add(new Test.Simple(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_COMPRESS, EC_Consts.KA_ECDH), ecdhExpected));
        tests.add(new Test.Simple(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_ONE, EC_Consts.KA_ECDH), ExpectedValue.FAILURE));
        tests.add(new Test.Simple(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_ZERO, EC_Consts.KA_ECDH), ExpectedValue.FAILURE));
        tests.add(new Test.Simple(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_MAX, EC_Consts.KA_ECDH), ExpectedValue.FAILURE));
        tests.add(new Test.Simple(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_FULLRANDOM, EC_Consts.KA_ECDH), ExpectedValue.FAILURE));
        tests.add(new Test.Simple(new Command.ECDSA(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, null), ecdsaExpected));

        return Test.Compound.function((testArray) -> {
            Function<ExpectedValue, String> shouldHave = (expected) -> {
                switch (expected) {
                    case SUCCESS:
                        return "succeeded";
                    case FAILURE:
                        return "failed";
                    case ANY:
                    default:
                        return "";
                }
            };

            for (int i = 0; i < testArray.length; ++i) {
                Test t = testArray[i];
                if (!t.ok()) {
                    if (i == 0) { // generate
                        return new Result(Value.FAILURE, "The generation of a key should have " + shouldHave.apply(generateExpected) + ", but it did not.");
                    } else if (i == 2) { // ecdh compress
                        return new Result(Value.FAILURE, "The ECDH should have " + shouldHave.apply(ecdhExpected) + ", but it did not.");
                    } else if (i == 1) { // ecdh normal
                        return new Result(Value.FAILURE, "The ECDH of a compressed point should have " + shouldHave.apply(ecdhCompressExpected) + ", but it did not.");
                    } else if (i <= 6) { // ecdh wrong, should fail
                        return new Result(Value.FAILURE, "The ECDH of a corrupted point should have failed, but it did not.");
                    } else { // ecdsa
                        return new Result(Value.FAILURE, "The ECDSA should have " + shouldHave.apply(ecdsaExpected) + ", but it did not.");
                    }
                }
            }
            return new Result(Value.SUCCESS);
        }, description, tests.toArray(new Test[0]));
    }

    /**
     * @param cardManager            cardManager to send APDU through
     * @param category               category to test
     * @param field                  field to test (KeyPair.ALG_EC_FP || KeyPair.ALG_EC_F2M)
     * @param setExpected            expected result of the Set (curve) command
     * @param generateExpected       expected result of the Generate command
     * @param ecdhExpected           expected result of the ordinary ECDH command
     * @param ecdhCompressedExpected expected result of the ECDH command with a compressed point.
     * @param ecdsaExpected          expected result of the ordinary ECDSA command
     * @param description            compound test description
     * @return tests to run
     */
    List<Test> defaultCategoryTests(CardMngr cardManager, String category, byte field, ExpectedValue setExpected, ExpectedValue generateExpected, ExpectedValue ecdhExpected, ExpectedValue ecdhCompressedExpected, ExpectedValue ecdsaExpected, String description) {
        List<Test> tests = new LinkedList<>();
        Map<String, EC_Curve> curves = dataStore.getObjects(EC_Curve.class, category);
        if (curves == null)
            return tests;
        for (Map.Entry<String, EC_Curve> entry : curves.entrySet()) {
            EC_Curve curve = entry.getValue();
            if (curve.getField() == field && (curve.getBits() == cfg.bits || cfg.all)) {
                tests.add(new Test.Simple(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), field), ExpectedValue.SUCCESS));
                tests.add(new Test.Simple(new Command.Set(cardManager, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()), setExpected));
                tests.add(defaultCurveTests(cardManager, generateExpected, ecdhExpected, ecdhCompressedExpected, ecdsaExpected, description));
                tests.add(new Test.Simple(new Command.Cleanup(cardManager), ExpectedValue.ANY));
            }
        }

        return tests;
    }
}
