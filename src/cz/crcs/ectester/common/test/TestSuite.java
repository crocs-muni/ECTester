package cz.crcs.ectester.common.test;

import cz.crcs.ectester.common.output.TestWriter;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class TestSuite {
    protected String name;
    protected String description;
    private TestWriter writer;
    private Test running;

    public TestSuite(TestWriter writer, String name, String description) {
        this.writer = writer;
        this.name = name;
        this.description = description;
    }

    /**
     * Run the <code>TestSuite</code>.
     */
    public void run() {
        writer.begin(this);
        try {
            runTests();
        } catch (TestException e) {
            writer.outputError(running, e);
        } catch (Exception e) {
            writer.end();
            throw new TestSuiteException(e);
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
    protected Test runTest(Test t) {
        running = t;
        t.run();
        running = null;
        return t;
    }

    /**
     * Run the given test, output it and return it back.
     *
     * @param t The test to run.
     * @return The test that was run.
     * @throws TestException
     */
    protected Test doTest(Test t) {
        runTest(t);
        writer.outputTest(t);
        return t;
    }

    /**
     *
     */
    protected abstract void runTests() throws Exception;

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

}
