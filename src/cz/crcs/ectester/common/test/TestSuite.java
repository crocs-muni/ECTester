package cz.crcs.ectester.common.test;

import cz.crcs.ectester.common.output.TestWriter;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class TestSuite {
    protected String name;
    protected String description;
    protected TestWriter writer;

    public TestSuite(TestWriter writer, String name, String description) {
        this.writer = writer;
        this.name = name;
        this.description = description;
    }

    public void run() throws TestException {
        writer.begin(this);
        try {
            runTests();
        } catch (Exception e) {
            throw new TestException(e);
        }
        writer.end();
    }

    /**
     * Run the given test and return it back.
     *
     * @param t The test to run.
     * @return The test that was run.
     * @throws TestException
     */
    protected Test runTest(Test t) throws TestException {
        t.run();
        return t;
    }

    /**
     * Run the given test, output it and return it back.
     *
     * @param t The test to run.
     * @return The test that was run.
     * @throws TestException
     */
    protected Test doTest(Test t) throws TestException {
        t.run();
        writer.outputTest(t);
        return t;
    }

    protected abstract void runTests() throws Exception;

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

}
