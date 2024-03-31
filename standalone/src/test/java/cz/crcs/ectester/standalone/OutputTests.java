package cz.crcs.ectester.standalone;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junitpioneer.jupiter.StdIo;
import org.junitpioneer.jupiter.StdOut;

import static org.junit.jupiter.api.Assertions.assertFalse;

public class OutputTests {

    @SuppressWarnings("JUnitMalformedDeclaration")
    @ParameterizedTest
    @ValueSource(strings = {"text", "xml", "yml"})
    @StdIo()
    public void formats(String format, StdOut out) {
        ECTesterStandalone.main(new String[]{"test", "-f", format, "default", "SunEC"});
        String s = out.capturedString();
        assertFalse(s.isEmpty());
    }
}
