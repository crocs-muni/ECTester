package cz.crcs.ectester.standalone.output;

import cz.crcs.ectester.common.output.BaseTextTestWriter;
import cz.crcs.ectester.common.test.Testable;

import java.io.PrintStream;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class TextTestWriter extends BaseTextTestWriter {
    public TextTestWriter(PrintStream output) {
        super(output);
    }

    @Override
    protected String testableString(Testable t) {
        return "";
    }
}