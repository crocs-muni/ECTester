package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.test.TestException;
import cz.crcs.ectester.common.output.TestWriter;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class TestRunner {
    private TestSuite suite;
    private TestWriter writer;

    public TestRunner(TestSuite suite, TestWriter writer) {
        this.suite = suite;
        this.writer = writer;
    }

    public void run() throws TestException {
        writer.begin(suite);
        for (Test t : suite.getTests()) {
            if (!t.hasRun()) {
                t.run();
                writer.outputTest(t);
            }
        }
        writer.end();
    }
}
