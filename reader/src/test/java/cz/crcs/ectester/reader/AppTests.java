package cz.crcs.ectester.reader;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.DisabledUntil;
import org.junitpioneer.jupiter.StdIo;
import org.junitpioneer.jupiter.StdOut;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class AppTests {

    @Test
    @StdIo()
    public void help(StdOut out) {
        ECTesterReader.main(new String[]{"-h"});
        String s = out.capturedString();
        assertTrue(s.contains("ECTesterReader"));
    }

    @Test
    @StdIo()
    public void listSuites(StdOut out) {
        ECTesterReader.main(new String[]{"--list-suites"});
        String s = out.capturedString();
        assertTrue(s.contains("default test suite"));
    }

    @Test
    @StdIo()
    public void listData(StdOut out) {
        ECTesterReader.main(new String[]{"--list-named"});
        String s = out.capturedString();
        assertTrue(s.contains("secg"));
    }

    // Add StdIo to all the suite tests when this is resolved: https://github.com/junit-pioneer/junit-pioneer/issues/822

    @Test
    public void defaultSuite() {
        ECTesterReader.main(new String[]{"-t", "default", "-s"});
    }

    @Test
    public void testVectorSuite() {
        ECTesterReader.main(new String[]{"-t", "test-vectors", "-s"});
    }

    @Test
    public void compressionSuite() {
        ECTesterReader.main(new String[]{"-t", "compression", "-s"});
    }

    @Test
    public void wrongSuite() {
        ECTesterReader.main(new String[]{"-t", "wrong", "-s", "-y"});
    }

    @Test
    public void degenerateSuite() {
        ECTesterReader.main(new String[]{"-t", "degenerate", "-s", "-y"});
    }

    @Test
    public void cofactorSuite() {
        ECTesterReader.main(new String[]{"-t", "cofactor", "-s", "-y"});
    }

    @Test
    public void compositeSuite() {
        ECTesterReader.main(new String[]{"-t", "composite", "-s", "-y"});
    }

    @Test
    public void invalidSuite() {
        ECTesterReader.main(new String[]{"-t", "invalid", "-s", "-y"});
    }

    @Test
    public void edgeCasesSuite() {
        ECTesterReader.main(new String[]{"-t", "edge-cases", "-s", "-y"});
    }

    @Test
    public void signatureSuite() {
        ECTesterReader.main(new String[]{"-t", "signature", "-s"});
    }

    @Test
    public void twistSuite() {
        ECTesterReader.main(new String[]{"-t", "twist", "-s", "-y"});
    }

    @Test
    public void miscellaneousSuite() {
        ECTesterReader.main(new String[]{"-t", "miscellaneous", "-s", "-y"});
    }
}
