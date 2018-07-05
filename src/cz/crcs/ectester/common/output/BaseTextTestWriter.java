package cz.crcs.ectester.common.output;

import cz.crcs.ectester.common.cli.Colors;
import cz.crcs.ectester.common.test.*;

import java.io.PrintStream;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * An absctract basis of a TextTestWriter, which outputs in a human readable format, into console.
 * Requires the implementation of:
 * <code>String testableString(Testable t)</code>
 * <code>String deviceString(TestSuite t)</code>
 *
 * @author Jan Jancar johny@neuromancer.sk
 */
public abstract class BaseTextTestWriter implements TestWriter {
    private PrintStream output;

    public static int BASE_WIDTH = 105;

    public BaseTextTestWriter(PrintStream output) {
        this.output = output;
    }

    @Override
    public void begin(TestSuite suite) {
        output.println("═══ Running test suite: " + Colors.bold(suite.getName()) + " ═══");
        for (String d : suite.getDescription()) {
            output.println("═══ " + d);
        }
        DateFormat dateFormat = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss");
        Date date = new Date();
        output.println("═══ Date: " + dateFormat.format(date));
        output.print(deviceString(suite));
    }

    /**
     * @param t
     * @return
     */
    protected abstract String testableString(Testable t);

    /**
     * @param suite
     * @return
     */
    protected abstract String deviceString(TestSuite suite);

    private String testString(Test t, String prefix, int index) {
        boolean compound = t instanceof CompoundTest;

        Result result = t.getResult();

        StringBuilder out = new StringBuilder();
        out.append(t.ok() ? Colors.ok(" OK ") : Colors.error("NOK "));
        out.append(compound ? "┳ " : "━ ");
        int width = BASE_WIDTH - (prefix.length() + out.length());
        String widthSpec = "%-" + String.valueOf(width) + "s";
        String desc = ((prefix.equals("")) ? "(" + index + ") " : "") + t.getDescription();
        out.append(String.format(widthSpec, desc));
        out.append(" ┃ ");
        Colors.Foreground valueColor;
        if (result.getValue().ok()) {
            valueColor = Colors.Foreground.GREEN;
        } else if (result.getValue().equals(Result.Value.ERROR)) {
            valueColor = Colors.Foreground.RED;
        } else {
            valueColor = Colors.Foreground.YELLOW;
        }
        out.append(Colors.colored(String.format("%-9s", result.getValue().name()), Colors.Attribute.BOLD, valueColor));
        out.append(" ┃ ");

        if (compound) {
            CompoundTest test = (CompoundTest) t;
            out.append(String.valueOf(result.getCause()));
            out.append(System.lineSeparator());
            Test[] tests = test.getStartedTests();
            for (int i = 0; i < tests.length; ++i) {
                if (i == tests.length - 1) {
                    out.append(prefix).append("    ┗ ");
                    out.append(testString(tests[i], prefix + "      ", index));
                } else {
                    out.append(prefix).append("    ┣ ");
                    out.append(testString(tests[i], prefix + "    ┃ ", index));
                }

                if (i != tests.length - 1) {
                    out.append(System.lineSeparator());
                }
            }
        } else {
            SimpleTest<? extends BaseTestable> test = (SimpleTest<? extends BaseTestable>) t;
            out.append(testableString(test.getTestable()));
        }
        return out.toString();
    }

    @Override
    public void outputTest(Test t, int index) {
        if (!t.hasRun())
            return;
        output.println(testString(t, "", index));
        output.flush();
    }

    private String errorString(Throwable error) {
        StringBuilder sb = new StringBuilder();
        for (Throwable t = error; t != null; t = t.getCause()) {
            sb.append("═══ ").append(t.toString()).append(" ═══");
            sb.append(System.lineSeparator());
        }
        sb.append("═══ ═══").append(System.lineSeparator());
        for (StackTraceElement s : error.getStackTrace()) {
            sb.append("═══ ").append(s.toString()).append(" ═══");
            sb.append(System.lineSeparator());
        }
        return sb.toString();
    }

    @Override
    public void outputError(Test t, Throwable cause, int index) {
        output.println(testString(t, "", index));
        output.print(errorString(cause));
        output.flush();
    }

    @Override
    public void end() {
    }
}
