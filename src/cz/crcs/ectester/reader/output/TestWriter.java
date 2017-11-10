package cz.crcs.ectester.reader.output;

import cz.crcs.ectester.reader.test.Test;
import cz.crcs.ectester.reader.test.TestSuite;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public interface TestWriter {
    void begin(TestSuite suite);

    void outputTest(Test t);

    void end();
}
