package cz.crcs.ectester.common.output;

import cz.crcs.ectester.common.test.*;

import java.io.PrintStream;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class BaseTextTestWriter implements TestWriter {
    private PrintStream output;

    public static int BASE_WIDTH = 90;

    public BaseTextTestWriter(PrintStream output) {
        this.output = output;
    }

    @Override
    public void begin(TestSuite suite) {
        output.println("═══ Running test suite: " + suite.getName() + " ═══");
        output.println("═══ " + suite.getDescription());
        output.print(deviceString(suite));
    }

    protected abstract String testableString(Testable t);

    protected abstract String deviceString(TestSuite suite);

    private String testString(Test t, String prefix) {
        boolean compound = t instanceof CompoundTest;

        Result result = t.getResult();

        StringBuilder out = new StringBuilder();
        out.append(t.ok() ? " OK " : "NOK ");
        out.append(compound ? "┳ " : "━ ");
        int width = BASE_WIDTH - (prefix.length() + out.length());
        String widthSpec = "%-" + String.valueOf(width) + "s";
        out.append(String.format(widthSpec, t.getDescription()));
        out.append(" ┃ ");
        out.append(String.format("%-9s", result.getValue().name()));
        out.append(" ┃ ");

        if (compound) {
            CompoundTest test = (CompoundTest) t;
            out.append(result.getCause().toString());
            out.append(System.lineSeparator());
            Test[] tests = test.getStartedTests();
            for (int i = 0; i < tests.length; ++i) {
                if (i == tests.length - 1) {
                    out.append(prefix).append("    ┗ ");
                    out.append(testString(tests[i], prefix + "      "));
                } else {
                    out.append(prefix).append("    ┣ ");
                    out.append(testString(tests[i], prefix + "    ┃ "));
                }

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
        output.println(testString(t, ""));
        output.flush();
    }

    private String errorString(Throwable error) {
        StringBuilder sb = new StringBuilder();
        for (Throwable t = error; t != null; t = t.getCause()) {
            sb.append("═══ ").append(t.toString()).append(" ═══");
            sb.append(System.lineSeparator());
        }
        return sb.toString();
    }

    @Override
    public void outputError(Test t, Throwable cause) {
        output.println(testString(t, ""));
        output.print(errorString(cause));
        output.flush();
    }

    @Override
    public void end() {
    }
}
