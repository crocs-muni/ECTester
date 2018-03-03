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
     *
     * @param t
     */
    void outputTest(Test t);

    /**
     *
     * @param t
     * @param cause
     */
    void outputError(Test t, Throwable cause);

    /**
     *
     */
    void end();
}
