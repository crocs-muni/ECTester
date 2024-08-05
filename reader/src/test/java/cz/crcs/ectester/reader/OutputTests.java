package cz.crcs.ectester.reader;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class OutputTests {

    @ParameterizedTest
    @ValueSource(strings = {"text", "xml", "yml"})
    public void formats(String format) {
        ECTesterReader.main(new String[]{"-t", "default", "-s", "-o", String.format("%s:out.%s", format, format),});
    }
}
