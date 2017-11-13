package cz.crcs.ectester.standalone.test;

import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.test.TestCallback;
import cz.crcs.ectester.common.test.TestException;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class KeyGenerationTest extends Test {
    private KeyGenerationTestable kg;
    private TestCallback<KeyGenerationTestable> callback;

    private KeyGenerationTest(KeyGenerationTestable kg, TestCallback<KeyGenerationTestable> callback) {
        this.kg = kg;
        this.callback = callback;
    }

    public static KeyGenerationTest expect(KeyGenerationTestable kg, Result.ExpectedValue expected) {
        return new KeyGenerationTest(kg, new TestCallback<KeyGenerationTestable>() {
            @Override
            public Result apply(KeyGenerationTestable keyGenerationTestable) {
                return new Result(Result.Value.fromExpected(expected, keyGenerationTestable.ok(), keyGenerationTestable.error()));
            }
        });
    }

    public static KeyGenerationTest function(KeyGenerationTestable ka, TestCallback<KeyGenerationTestable> callback) {
        return new KeyGenerationTest(ka, callback);
    }

    @Override
    public String getDescription() {
        return null;
    }

    @Override
    public void run() throws TestException {
        kg.run();
        result = callback.apply(kg);
        hasRun = true;
    }
}
