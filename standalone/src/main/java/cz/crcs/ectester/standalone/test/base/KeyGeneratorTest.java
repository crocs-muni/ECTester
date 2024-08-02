package cz.crcs.ectester.standalone.test.base;

import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.SimpleTest;
import cz.crcs.ectester.common.test.TestCallback;

import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class KeyGeneratorTest extends SimpleTest<KeyGeneratorTestable> {
    private KeyGeneratorTest(KeyGeneratorTestable kg, TestCallback<KeyGeneratorTestable> callback) {
        super(kg, callback);
    }

    public static KeyGeneratorTest expect(KeyGeneratorTestable kg, Result.ExpectedValue expected) {
        return new KeyGeneratorTest(kg, new TestCallback<KeyGeneratorTestable>() {
            @Override
            public Result apply(KeyGeneratorTestable keyGenerationTestable) {
                Result.Value value = Result.Value.fromExpected(expected, keyGenerationTestable.ok(), keyGenerationTestable.error());
                return new Result(value, value.description());
            }
        });
    }

    public static KeyGeneratorTest expectError(KeyGeneratorTestable kg, Result.ExpectedValue expected) {
        return new KeyGeneratorTest(kg, new TestCallback<KeyGeneratorTestable>() {
            @Override
            public Result apply(KeyGeneratorTestable keyGenerationTestable) {
                Result.Value value = Result.Value.fromExpected(expected, keyGenerationTestable.ok(), false);
                return new Result(value, value.description());
            }
        });
    }

    public static KeyGeneratorTest function(KeyGeneratorTestable ka, TestCallback<KeyGeneratorTestable> callback) {
        return new KeyGeneratorTest(ka, callback);
    }

    @Override
    public String getDescription() {
        String params = "";
        if (testable.getKeysize() != 0) {
            params = String.format("on (default %d-bit curve)", testable.getKeysize());
        } else if (testable.getSpec() instanceof ECGenParameterSpec) {
            String name = ((ECGenParameterSpec)testable.getSpec()).getName();
            params = String.format("on (%s)", name);
        } else if (testable.getSpec() instanceof ECParameterSpec) {
            params = "on (custom curve)";
        }
        return "KeyPairGenerator " + testable.getKpg().getAlgorithm() + " " + params;
    }
}
