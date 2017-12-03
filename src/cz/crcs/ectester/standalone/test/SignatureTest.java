package cz.crcs.ectester.standalone.test;

import cz.crcs.ectester.common.test.SimpleTest;
import cz.crcs.ectester.common.test.TestCallback;
import cz.crcs.ectester.common.test.TestException;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class SignatureTest extends SimpleTest<SignatureTestable> {
    private SignatureTest(SignatureTestable sig, TestCallback<SignatureTestable> callback) {
        super(sig, callback);
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
