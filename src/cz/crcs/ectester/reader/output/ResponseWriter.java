package cz.crcs.ectester.reader.output;

import cz.crcs.ectester.reader.Util;
import cz.crcs.ectester.reader.response.Response;

import java.io.PrintStream;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class ResponseWriter {
    private PrintStream output;

    public ResponseWriter(PrintStream output) {
        this.output = output;
    }

    public String responseSuffix(Response r) {
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

    public void outputResponse(Response r) {
        String out = "";
        out += String.format("%-70s:", r.getDescription()) + " : ";
        out += responseSuffix(r);
        output.println(out);
        output.flush();
    }
}
