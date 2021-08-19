package cz.crcs.ectester.standalone.test.base;

import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.SimpleTest;
import cz.crcs.ectester.common.test.TestCallback;

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
        return "KeyPairGenerator " + testable.getKpg().getAlgorithm();
    }
}
