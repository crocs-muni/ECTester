package cz.crcs.ectester.common.test;

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
        for (Runnable t : suite.getRunnables()) {
            if (!t.hasRun()) {
                t.run();
                if (t instanceof Test) {
                    writer.outputTest((Test) t);
                }
            }
        }
        writer.end();
    }
}
