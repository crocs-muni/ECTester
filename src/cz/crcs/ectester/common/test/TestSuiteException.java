package cz.crcs.ectester.common.test;

/**
 * An unexpected exception was thrown while running a TestSuite, outside Test
 * or a Testable.
 *
 * @author Jan Jancar johny@neuromancer.sk
 */
@SuppressWarnings("serial")
public class TestSuiteException extends RuntimeException {
    public TestSuiteException(Throwable e) {
        super(e);
    }
}
