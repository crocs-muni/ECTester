package cz.crcs.ectester.common.output;

import javax.xml.parsers.ParserConfigurationException;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.util.LinkedList;
import java.util.List;

public abstract class BaseFileTestWriter extends TeeTestWriter {

    public BaseFileTestWriter(String defaultFormat, boolean systemOut, String[] files) throws ParserConfigurationException, FileNotFoundException {
        int fLength = files == null ? 0 : files.length;
        List<TestWriter> lWriters = new LinkedList<>();
        if (systemOut) {
            lWriters.add(createWriter(defaultFormat, System.out));
        }
        for (int i = 0; i < fLength; ++i) {
            String[] matched = matchName(files[i]);
            String format = matched[0];
            String fName = matched[1];
            lWriters.add(createWriter(format, new PrintStream(new FileOutputStream(fName))));
        }
        writers = lWriters.toArray(new TestWriter[0]);
    }

    protected abstract String[] matchName(String name);

    protected abstract TestWriter createWriter(String format, PrintStream out) throws ParserConfigurationException;
}
