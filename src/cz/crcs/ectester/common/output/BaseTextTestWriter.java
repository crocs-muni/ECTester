package cz.crcs.ectester.common.output;

import cz.crcs.ectester.common.test.*;

import java.io.PrintStream;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class BaseTextTestWriter implements TestWriter {
    private PrintStream output;

    public static int BASE_WIDTH = 80;

    public BaseTextTestWriter(PrintStream output) {
        this.output = output;
    }

    @Override
    public void begin(TestSuite suite) {
        output.println("═══ Running test suite: " + suite.getName() + " ═══");
        output.println("═══ " + suite.getDescription());
    }

    protected abstract String testableString(Testable t);

    private String testString(Test t, int offset) {
        if (!t.hasRun()) {
            return null;
        }
        boolean compound = t instanceof CompoundTest;

        StringBuilder out = new StringBuilder();
        out.append(t.ok() ? " OK " : "NOK ");
        out.append(compound ? "┳ " : "━ ");
        int width = BASE_WIDTH - (offset + out.length());
        String widthSpec = "%-" + String.valueOf(width) + "s";
        out.append(String.format(widthSpec, t.getDescription()));
        out.append(" ┃ ");
        out.append(String.format("%-9s", t.getResultValue().name()));
        out.append(" ┃ ");

        if (compound) {
            CompoundTest test = (CompoundTest) t;
            out.append(test.getResultCause());
            out.append(System.lineSeparator());
            Test[] tests = test.getTests();
            for (int i = 0; i < tests.length; ++i) {
                if (i == tests.length - 1) {
                    out.append("    ┗ ");
                } else {
                    out.append("    ┣ ");
                }
                out.append(testString(tests[i], offset + 6));
                if (i != tests.length - 1) {
                    out.append(System.lineSeparator());
                }
            }
        } else {
            SimpleTest test = (SimpleTest) t;
            out.append(testableString(test.getTestable()));
        }
        return out.toString();
    }

    @Override
    public void outputTest(Test t) {
        if (!t.hasRun())
            return;
        output.println(testString(t, 0));
        output.flush();
    }

    @Override
    public void end() {
    }
}
