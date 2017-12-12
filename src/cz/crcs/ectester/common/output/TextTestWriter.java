package cz.crcs.ectester.common.output;

import cz.crcs.ectester.common.test.CompoundTest;
import cz.crcs.ectester.common.test.SimpleTest;
import cz.crcs.ectester.common.test.Test;
import cz.crcs.ectester.common.test.TestSuite;

import java.io.PrintStream;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class TextTestWriter implements TestWriter {
    private PrintStream output;
    private TestableWriter testableWriter;

    public static int BASE_WIDTH = 76;

    public TextTestWriter(PrintStream output) {
        this.output = output;
        this.testableWriter = new TestableWriter(output);
    }

    @Override
    public void begin(TestSuite suite) {
        output.println("=== Running test suite: " + suite.getName() + " ===");
        output.println("=== " + suite.getDescription());
    }

    private String testString(Test t, int offset) {
        if (!t.hasRun()) {
            return null;
        }

        StringBuilder out = new StringBuilder();
        out.append(t.ok() ? "OK  " : "NOK ");
        out.append("━ ");
        int width = BASE_WIDTH - (offset + out.length());
        String widthSpec = "%-" + String.valueOf(width) + "s";
        out.append(String.format(widthSpec, t.getDescription()));
        out.append(" ┃ ");
        out.append(String.format("%-9s", t.getResultValue().name()));
        out.append(" ┃ ");

        if (t instanceof CompoundTest) {
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
            out.append(testableWriter.outputTestableSuffix(test.getTestable()));
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
