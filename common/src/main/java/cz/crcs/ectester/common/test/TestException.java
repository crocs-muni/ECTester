package cz.crcs.ectester.common.test;

/**
 * A TestException is an Exception that can be thrown during the running of a Testable,
 * or a Test. It means that the Testable/TestSuite encountered an unexpected error
 * and has to terminate.
 *
 * @author Jan Jancar johny@neuromancer.sk
 */
@SuppressWarnings("serial")
public class TestException extends RuntimeException {
    public TestException(Throwable e) {
        super(e);
    }
}
