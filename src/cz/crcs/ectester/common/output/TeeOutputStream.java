package cz.crcs.ectester.common.output;

import java.io.IOException;
import java.io.OutputStream;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class TeeOutputStream extends OutputStream {
    private OutputStream[] outputs;

    public TeeOutputStream(OutputStream... outputs) {
        this.outputs = outputs;
    }

    @Override
    public void write(int b) throws IOException {
        for (OutputStream out : outputs) {
            out.write(b);
        }
    }

    @Override
    public void flush() throws IOException {
        for (OutputStream out : outputs) {
            out.flush();
        }
    }

    @Override
    public void close() throws IOException {
        for (OutputStream out : outputs) {
            out.close();
        }
    }
}
