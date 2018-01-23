package cz.crcs.ectester.common.test;

/**
 * A TestException is an Exception that can be thrown during the running of a Testable,
 * or a TestSuite. It means that the Testable/TestSuite encountered an unexpected error
 * during it's run which points to an error in ECTester or it's runtime environment.cd
 * @author Jan Jancar johny@neuromancer.sk
 */
public class TestException extends Exception {
    public TestException(Throwable e) {
        super(e);
    }
}
