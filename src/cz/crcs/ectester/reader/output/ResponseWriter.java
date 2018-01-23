package cz.crcs.ectester.reader.output;

import cz.crcs.ectester.common.util.CardUtil;
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
                suffix.append(" ").append(CardUtil.getSWString(sw));
            }
        }
        if (suffix.length() == 0) {
            suffix.append(" [").append(CardUtil.getSW(r.getNaturalSW())).append(String.format(" 0x%04x", r.getNaturalSW())).append("]");
        }
        return String.format("%4d ms ┃ %s", r.getDuration() / 1000000, suffix);
    }

    public String responseString(Response r) {
        String out = "";
        out += String.format("%-70s", r.getDescription()) + " ┃ ";
        out += responseSuffix(r);
        return out;
    }

    public void outputResponse(Response r) {
        output.println(responseString(r));
        output.flush();
    }
}
