package cz.crcs.ectester.standalone.test;

import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.test.TestCallback;
import cz.crcs.ectester.common.test.TestException;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class SignatureTest extends Test {
    private SignatureTestable sig;
    private TestCallback<SignatureTestable> callback;

    private SignatureTest(SignatureTestable sig, TestCallback<SignatureTestable> callback) {
        this.sig = sig;
        this.callback = callback;
    }

    @Override
    public String getDescription() {
        return null;
    }

    @Override
    public void run() throws TestException {
        sig.run();
        result = callback.apply(sig);
        hasRun = true;
    }
}
