package cz.crcs.ectester.reader.output;

import cz.crcs.ectester.common.output.BaseFileTestWriter;
import cz.crcs.ectester.common.output.TestWriter;

import javax.xml.parsers.ParserConfigurationException;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.util.regex.Pattern;

/**
 * @author Jan Jancar johny@neuromancer.sk
 */
public class FileTestWriter extends BaseFileTestWriter {

    private static final Pattern PREFIX = Pattern.compile("(text|xml|yaml|yml):.+");

    public FileTestWriter(String defaultFormat, boolean systemOut, String[] files) throws ParserConfigurationException, FileNotFoundException {
        super(defaultFormat, systemOut, files);
    }

    @Override
    protected String[] matchName(String name) {
        String[] result = new String[2];
        if (PREFIX.matcher(name).matches()) {
            result = name.split(":", 2);
        } else {
            result[0] = null;
            result[1] = name;
        }
        return result;
    }

    protected TestWriter createWriter(String format, PrintStream out) throws ParserConfigurationException {
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
