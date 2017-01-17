package cz.crcs.ectester.reader;

import java.io.FileWriter;
import java.io.IOException;

/**
 * @author Petr Svenda petr@svenda.com
 * @author Jan Jancar johny@neuromancer.sk
 */
public class DirtyLogger {
    FileWriter log;
    boolean systemOut;

    public DirtyLogger(String filePath) throws IOException {
        this(filePath, true);
    }

    public DirtyLogger(String filePath, boolean systemOut) throws IOException {
        if (filePath != null)
            this.log = new FileWriter(filePath);
        this.systemOut = systemOut;
    }

    public void println() {
        print("\n");
    }

    public void println(String logLine) {
        logLine += "\n";
        print(logLine);
    }

    public void print(String logLine) {
        if (systemOut) {
            System.out.print(logLine);
        }
        if (log != null) {
            try {
                log.write(logLine);
            } catch (IOException ignored) {
            }
        }
    }

    void flush() {
        try {
            if (log != null) log.flush();
        } catch (IOException ignored) {
        }
    }

    void close() throws IOException {
        if (log != null) log.close();
    }
}
