package cz.crcs.ectester.reader.output;

import cz.crcs.ectester.reader.test.Test;
import cz.crcs.ectester.reader.test.Result;
import cz.crcs.ectester.reader.test.TestSuite;

import java.io.PrintStream;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class TextTestWriter implements TestWriter {
    private PrintStream output;
    private ResponseWriter respWriter;

    public TextTestWriter(PrintStream output) {
        this.output = output;
        this.respWriter = new ResponseWriter(output);
    }

    @Override
    public void begin(TestSuite suite) {
        output.println("=== Running test suite: " + suite.getName() + " ===");
        output.println("=== " + suite.getDescription());
    }

    private String testPrefix(Test t) {
        return String.format("%-4s", t.getResultValue() == Result.Value.SUCCESS ? "OK" : "NOK");
    }

    private String testString(Test t) {
        if (!t.hasRun())
            return null;

        StringBuilder out = new StringBuilder();
        if (t instanceof Test.Simple) {
            Test.Simple test = (Test.Simple) t;
            out.append(String.format("%-70s:", testPrefix(t) + " : " + test.getDescription())).append(" : ");
            out.append(respWriter.responseSuffix(test.getResponse()));
        } else if (t instanceof Test.Compound) {
            Test.Compound test = (Test.Compound) t;
            Test[] tests = test.getTests();
            for (int i = 0; i < tests.length; ++i) {
                if (i == 0) {
                    out.append(" /- ");
                } else if (i == tests.length - 1) {
                    out.append(" \\- ");
                } else {
                    out.append(" |  ");
                }
                out.append(testString(tests[i])).append(System.lineSeparator());
            }
            out.append(String.format("%-70s", testPrefix(t) + " : " + test.getDescription()));
        }
        return out.toString();
    }

    @Override
    public void outputTest(Test t) {
        if (!t.hasRun())
            return;
        output.println(testString(t));
        output.flush();
    }

    @Override
    public void end() {
    }
}
