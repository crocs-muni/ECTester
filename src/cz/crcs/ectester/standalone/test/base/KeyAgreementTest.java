package cz.crcs.ectester.standalone.test.base;

import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.common.test.SimpleTest;
import cz.crcs.ectester.common.test.TestCallback;

import javax.xml.bind.DatatypeConverter;
import java.util.Arrays;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class KeyAgreementTest extends SimpleTest<KeyAgreementTestable> {
    private KeyAgreementTest(KeyAgreementTestable ka, TestCallback<KeyAgreementTestable> callback) {
        super(ka, callback);
    }

    public static KeyAgreementTest match(KeyAgreementTestable ka, byte[] expectedSecret) {
        return new KeyAgreementTest(ka, new TestCallback<KeyAgreementTestable>() {
            @Override
            public Result apply(KeyAgreementTestable ka) {
                if (Arrays.equals(ka.getSecret(), expectedSecret)) {
                    return new Result(Result.Value.SUCCESS, "The KeyAgreement result matched the expected derived secret.");
                } else {
                    String expected = expectedSecret == null ? "null" : DatatypeConverter.printHexBinary(expectedSecret);
                    String actual = ka.getSecret() == null ? "null" : DatatypeConverter.printHexBinary(ka.getSecret());
                    return new Result(Result.Value.FAILURE, "The KeyAgreement result did not match the expected derived secret.\n" +
                            "Expected: " + expected +
                            "\nActual:   " + actual);
                }
            }
        });
    }

    public static KeyAgreementTest expect(KeyAgreementTestable ka, Result.ExpectedValue expected) {
        return new KeyAgreementTest(ka, new TestCallback<KeyAgreementTestable>() {
            @Override
            public Result apply(KeyAgreementTestable keyAgreementTestable) {
                Result.Value value = Result.Value.fromExpected(expected, keyAgreementTestable.ok(), keyAgreementTestable.error());
                return new Result(value, value.description());
            }
        });
    }

    public static KeyAgreementTest function(KeyAgreementTestable ka, TestCallback<KeyAgreementTestable> callback) {
        return new KeyAgreementTest(ka, callback);
    }

    @Override
    public String getDescription() {
        String keyAlgo = testable.getKeyAlgorithm() == null ? "" : " (" + testable.getKeyAlgorithm() + ")";
        return "KeyAgreement " + testable.getKa().getAlgorithm() + keyAlgo;
    }
}
