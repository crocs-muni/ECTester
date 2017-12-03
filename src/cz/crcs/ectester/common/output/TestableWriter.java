package cz.crcs.ectester.common.output;

import cz.crcs.ectester.common.test.BaseTestable;

import java.io.OutputStream;
import java.io.PrintStream;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class TestableWriter {
    private PrintStream output;

    public TestableWriter(PrintStream output) {
        this.output = output;
    }

    public TestableWriter(OutputStream output) {
        this(new PrintStream(output));
    }


    public String outputTestableMeta(BaseTestable t) {
        return null;
    }

    public void writeTestableMeta(BaseTestable t) {

    }

    public String outputTestable(BaseTestable t) {
        return null;
    }

    public void writeTestable(BaseTestable t) {

    }
}
