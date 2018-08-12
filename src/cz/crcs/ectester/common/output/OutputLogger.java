package cz.crcs.ectester.common.output;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Petr Svenda petr@svenda.com
 * @author Jan Jancar johny@neuromancer.sk
 */
public class OutputLogger {
    private OutputStream out;
    private PrintStream print;

    public OutputLogger(boolean systemOut, String... filePaths) throws IOException {
        List<OutputStream> streams = new LinkedList<>();
        for (String filePath : filePaths) {
            if (filePath != null) {
                streams.add(new FileOutputStream(filePath));
            }
        }
        if (systemOut) {
            streams.add(System.out);
        }
        this.out = new TeeOutputStream(streams.toArray(new OutputStream[0]));
        this.print = new PrintStream(this.out);
    }

    public OutputLogger(String filePath) throws IOException {
        this(true, filePath);
    }

    public OutputStream getOutputStream() {
        return this.out;
    }

    public PrintStream getPrintStream() {
        return this.print;
    }

    public void println() {
        print.println();
    }

    public void println(String logLine) {
        print.println(logLine);
    }

    public void print(String logLine) {
        print.print(logLine);
    }

    public void flush() {
        print.flush();
    }

    public void close() {
        print.close();
    }
}
