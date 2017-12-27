package cz.crcs.ectester.reader.output;

import cz.crcs.ectester.common.output.BaseTextTestWriter;
import cz.crcs.ectester.common.test.Testable;
import cz.crcs.ectester.reader.test.CommandTestable;

import java.io.PrintStream;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class TextTestWriter extends BaseTextTestWriter {
    private ResponseWriter writer;

    public TextTestWriter(PrintStream output) {
        super(output);
        this.writer = new ResponseWriter(output);
    }

    @Override
    protected String testableString(Testable t) {
        if (t instanceof CommandTestable) {
            CommandTestable cmd = (CommandTestable) t;
            return writer.responseSuffix(cmd.getResponse());
        }
        return "";
    }
}
