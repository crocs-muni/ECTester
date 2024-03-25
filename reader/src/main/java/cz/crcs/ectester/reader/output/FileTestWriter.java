package cz.crcs.ectester.reader.output;

import cz.crcs.ectester.common.output.TeeTestWriter;
import cz.crcs.ectester.common.output.TestWriter;

import javax.xml.parsers.ParserConfigurationException;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.util.regex.Pattern;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class FileTestWriter extends TeeTestWriter {

    private static final Pattern PREFIX = Pattern.compile("(text|xml|yaml|yml):.+");

    public FileTestWriter(String defaultFormat, boolean systemOut, String[] files) throws ParserConfigurationException, FileNotFoundException {
        int fLength = files == null ? 0 : files.length;
        writers = new TestWriter[systemOut ? fLength + 1 : fLength];
        if (systemOut) {
            writers[0] = createWriter(defaultFormat, System.out);
        }
        for (int i = 0; i < fLength; ++i) {
            String fName = files[i];
            String format = null;
            if (PREFIX.matcher(fName).matches()) {
                String[] split = fName.split(":", 2);
                format = split[0];
                fName = split[1];
            }
            writers[i + 1] = createWriter(format, new PrintStream(new FileOutputStream(fName)));
        }
    }

    private TestWriter createWriter(String format, PrintStream out) throws ParserConfigurationException {
        if (format == null) {
            return new TextTestWriter(out);
        }
        switch (format) {
            case "text":
                return new TextTestWriter(out);
            case "xml":
                return new XMLTestWriter(out);
            case "yaml":
            case "yml":
                return new YAMLTestWriter(out);
            default:
                return null;
        }
    }
}
