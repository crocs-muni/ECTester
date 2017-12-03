package cz.crcs.ectester.standalone.test;

import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.SimpleTest;
import cz.crcs.ectester.common.test.TestCallback;
import cz.crcs.ectester.common.test.TestException;

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
                return new Result(Result.Value.fromExpected(expected, keyGenerationTestable.ok(), keyGenerationTestable.error()));
            }
        });
    }

    public static KeyGeneratorTest function(KeyGeneratorTestable ka, TestCallback<KeyGeneratorTestable> callback) {
        return new KeyGeneratorTest(ka, callback);
    }

    @Override
    public String getDescription() {
        return null;
    }

    @Override
    public void run() throws TestException {
        if (hasRun)
            return;
        testable.run();
        result = callback.apply(testable);
        hasRun = true;
    }
}
