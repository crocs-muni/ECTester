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
     * @param t
     * @param index
     */
    void outputTest(Test t, int index);

    /**
     * @param t
     * @param cause
     * @param index
     */
    void outputError(Test t, Throwable cause, int index);

    /**
     *
     */
    void end();
}
