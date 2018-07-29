package cz.crcs.ectester.common.test;

import cz.crcs.ectester.common.output.TestWriter;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class TestSuite {
    protected String name;
    protected String[] description;
    private TestWriter writer;
    private Test running;
    private int ran = 0;
    private int runFrom = 0;
    private int runTo = -1;

    public TestSuite(TestWriter writer, String name, String... description) {
        this.writer = writer;
        this.name = name;
        this.description = description;
    }

    /**
     * Run the <code>TestSuite</code>.
     */
    public void run() {
        run(0);
    }

    public void run(int from) {
        run(from, -1);
    }

    public void run(int from, int to) {
        this.runFrom = from;
        this.runTo = to;
        writer.begin(this);
        try {
            runTests();
        } catch (TestException e) {
            writer.outputError(running, e, ran);
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
    protected <T extends Test> T runTest(T t) {
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
    protected <T extends Test> T doTest(T t) {
        if (ran >= runFrom && (runTo < 0 || ran <= runTo)) {
            runTest(t);
            writer.outputTest(t, ran);
        }
        ran++;
        return t;
    }

    /**
     *
     */
    protected abstract void runTests() throws Exception;

    public String getName() {
        return name;
    }

    public String[] getDescription() {
        return description;
    }

    public String getTextDescription() {
        return String.join(System.lineSeparator(), description);
    }

    public String toString() {
        return null;
    }

}
