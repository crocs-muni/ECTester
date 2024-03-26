package cz.crcs.ectester.standalone.test.base;

import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.SimpleTest;
import cz.crcs.ectester.common.test.TestCallback;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class SignatureTest extends SimpleTest<SignatureTestable> {
    private SignatureTest(SignatureTestable sig, TestCallback<SignatureTestable> callback) {
        super(sig, callback);
    }

    public static SignatureTest expect(SignatureTestable kg, Result.ExpectedValue expected) {
        return new SignatureTest(kg, new TestCallback<SignatureTestable>() {
            @Override
            public Result apply(SignatureTestable signatureTestable) {
                Result.Value value = Result.Value.fromExpected(expected, signatureTestable.ok(), signatureTestable.error());
                return new Result(value, value.description());
            }
        });
    }

    public static SignatureTest expectError(SignatureTestable kg, Result.ExpectedValue expected) {
        return new SignatureTest(kg, new TestCallback<SignatureTestable>() {
            @Override
            public Result apply(SignatureTestable signatureTestable) {
                Result.Value value = Result.Value.fromExpected(expected, signatureTestable.ok(), false);
                return new Result(value, value.description());
            }
        });
    }

    public static SignatureTest function(SignatureTestable ka, TestCallback<SignatureTestable> callback) {
        return new SignatureTest(ka, callback);
    }

    @Override
    public String getDescription() {
        return "Signature " + testable.getSig().getAlgorithm();
    }
}
