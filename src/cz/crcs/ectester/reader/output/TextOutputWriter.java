package cz.crcs.ectester.reader.output;

import cz.crcs.ectester.reader.Util;
import cz.crcs.ectester.reader.response.Response;
import cz.crcs.ectester.reader.test.Test;

import java.io.PrintStream;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class TextOutputWriter implements OutputWriter {
    private PrintStream output;

    public TextOutputWriter(PrintStream output) {
        this.output = output;
    }

    @Override
    public void begin() {
    }

    private String testPrefix(Test t) {
        return (t.ok() ? "OK" : "NOK");
    }

    private String responseSuffix(Response r) {
        StringBuilder suffix = new StringBuilder();
        for (int j = 0; j < r.getNumSW(); ++j) {
            short sw = r.getSW(j);
            if (sw != 0) {
                suffix.append(" ").append(Util.getSWString(sw));
            }
        }
        if (suffix.length() == 0) {
            suffix.append(" [").append(Util.getSW(r.getNaturalSW())).append("]");
        }
        return String.format("%4d ms : %s", r.getDuration() / 1000000, suffix);
    }

    @Override
    public void outputResponse(Response r) {
        String out = "";
        out += String.format("%-62s:", r.getDescription()) + " : ";
        out += responseSuffix(r);
        output.println(out);
        output.flush();
    }

    @Override
    public void outputTest(Test t) {
        if (!t.hasRun())
            return;

        String out = "";
        if (t instanceof Test.Simple) {
            Test.Simple test = (Test.Simple) t;
            out += String.format("%-62s:", testPrefix(t) + " " + test.getDescription()) + " : ";
            out += responseSuffix(test.getResponse());
        } else if (t instanceof  Test.Compound) {
            Test.Compound test = (Test.Compound) t;
            out += String.format("%-62s:", testPrefix(t) + " " + test.getDescription());
        }

        output.println(out);
        output.flush();
    }

    @Override
    public void end() {
    }
}
