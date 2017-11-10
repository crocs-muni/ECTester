package cz.crcs.ectester.reader.test;

import cz.crcs.ectester.reader.output.TestWriter;

import javax.smartcardio.CardException;

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

    public void run() throws CardException {
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
