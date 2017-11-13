package cz.crcs.ectester.standalone.test;

import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.test.TestCallback;
import cz.crcs.ectester.common.test.TestException;

import java.util.Arrays;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class KeyAgreementTest extends Test {
    private KeyAgreementTestable ka;
    private TestCallback<KeyAgreementTestable> callback;

    private KeyAgreementTest(KeyAgreementTestable ka, TestCallback<KeyAgreementTestable> callback) {
        this.ka = ka;
        this.callback = callback;
    }

    public static KeyAgreementTest match(KeyAgreementTestable ka, byte[] expectedSecret) {
        return new KeyAgreementTest(ka, new TestCallback<KeyAgreementTestable>() {
            @Override
            public Result apply(KeyAgreementTestable ka) {
                if (Arrays.equals(ka.getSecret(), expectedSecret)) {
                    return new Result(Result.Value.SUCCESS);
                } else {
                    return new Result(Result.Value.FAILURE);
                }
            }
        });
    }

    public static KeyAgreementTest expect(KeyAgreementTestable ka, Result.ExpectedValue expected) {
        return new KeyAgreementTest(ka, new TestCallback<KeyAgreementTestable>() {
            @Override
            public Result apply(KeyAgreementTestable keyAgreementTestable) {
                return new Result(Result.Value.fromExpected(expected, keyAgreementTestable.ok(), keyAgreementTestable.error()));
            }
        });
    }

    @Override
    public String getDescription() {
        return null;
    }

    @Override
    public void run() throws TestException {
        ka.run();
        result = callback.apply(ka);
        hasRun = true;
    }
}
