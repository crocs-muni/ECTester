package cz.crcs.ectester.reader;

import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Path;

public class OutputTests {

    @TempDir
    static Path tempDir;

    @ParameterizedTest
    @ValueSource(strings = {"text", "xml", "yml"})
    public void formats(String format) {
        Path outputFile = tempDir.resolve(String.format("out.%s", format));
        ECTesterReader.main(new String[]{"-t", "default", "-s", "-o", String.format("%s:%s", format, outputFile),});
    }
}
