package cz.crcs.ectester.common.output;

import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.test.TestSuite;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public interface TestWriter {
    /**
     * @param suite
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
