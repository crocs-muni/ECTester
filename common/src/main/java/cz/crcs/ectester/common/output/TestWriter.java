package cz.crcs.ectester.common.output;

import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.test.TestSuite;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public interface TestWriter {
    /**
     * Begin writing the <code>TestSuite suite</code>.
     * This should reset all the internal state of the writer
     * and prepare it to output tests from <code>suite</code>.
     * It may also write any header part of the output of the
     * writer but doesn't have to.
     *
     * @param suite The <code>TestSuite</code> to start writing.
     */
    void begin(TestSuite suite);

    /**
     * Begin the test (before it is run).
     * @param t Test to begin output of.
     */
    void beginTest(Test t);

    /**
     * End the test (after it is run, or errored out).
     * @param t Test to end output of.
     */
    void endTest(Test t);

    /**
     * @param t Test to output.
     * @param index Index of the test.
     */
    void outputTest(Test t, int index);

    /**
     * @param t Test to output the error from.
     * @param cause Throwable to output.
     * @param index Index of the test.
     */
    void outputError(Test t, Throwable cause, int index);

    /**
     * End writing the TestSuite.
     */
    void end();
}
