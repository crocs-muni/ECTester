package cz.crcs.ectester.reader;

import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.StdIo;
import org.junitpioneer.jupiter.StdOut;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
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
    @XFail(value = "JCardSim sometimes times-out.")
    public void defaultSuite() {
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> ECTesterReader.main(new String[]{"-t", "default", "-s"}));
    }

    @Test
    @XFail(value = "JCardSim sometimes times-out.")
    public void testVectorSuite() {
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> ECTesterReader.main(new String[]{"-t", "test-vectors", "-s"}));
    }

    @Test
    @XFail(value = "JCardSim sometimes times-out.")
    public void compressionSuite() {
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> ECTesterReader.main(new String[]{"-t", "compression", "-s"}));
    }

    @Test
    @XFail(value = "JCardSim sometimes times-out.")
    public void wrongSuite() {
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> ECTesterReader.main(new String[]{"-t", "wrong", "-s", "-y"}));
    }

    @Test
    @XFail(value = "JCardSim sometimes times-out.")
    public void degenerateSuite() {
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> ECTesterReader.main(new String[]{"-t", "degenerate", "-s", "-y"}));
    }

    @Test
    @XFail(value = "JCardSim sometimes times-out.")
    public void cofactorSuite() {
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> ECTesterReader.main(new String[]{"-t", "cofactor", "-s", "-y"}));
    }

    @Test
    @XFail(value = "JCardSim sometimes times-out.")
    public void compositeSuite() {
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> ECTesterReader.main(new String[]{"-t", "composite", "-s", "-y"}));
    }

    @Test
    @XFail(value = "JCardSim sometimes times-out.")
    public void invalidSuite() {
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> ECTesterReader.main(new String[]{"-t", "invalid", "-s", "-y"}));
    }

    @Test
    @XFail(value = "JCardSim sometimes times-out.")
    public void edgeCasesSuite() {
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> ECTesterReader.main(new String[]{"-t", "edge-cases", "-s", "-y"}));
    }

    @Test
    @XFail(value = "JCardSim sometimes times-out.")
    public void signatureSuite() {
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> ECTesterReader.main(new String[]{"-t", "signature", "-s"}));
    }

    @Test
    @XFail(value = "JCardSim sometimes times-out.")
    public void twistSuite() {
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> ECTesterReader.main(new String[]{"-t", "twist", "-s", "-y"}));
    }

    @Test
    @XFail(value = "JCardSim sometimes times-out.")
    public void miscellaneousSuite() {
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> ECTesterReader.main(new String[]{"-t", "miscellaneous", "-s", "-y"}));
    }

    @Test
    public void generate() {
        ECTesterReader.main(new String[]{"-g", "10", "-s", "-fp", "-o", "/dev/null", "-b", "256"});
    }

    @Test
    public void ecdh() {
        ECTesterReader.main(new String[]{"-dh", "-fp", "-b", "256", "-s"});
    }

    @Test
    public void ecdsa() {
        ECTesterReader.main(new String[]{"-dsa", "-fp", "-b", "256", "-s"});
    }

    @Test
    public void export() {
        ECTesterReader.main(new String[]{"-e", "-fp", "-b", "256", "-s", "-o", "/dev/null"});
    }

    @Test
    public void info() {
        ECTesterReader.main(new String[]{"-nf", "-s"});
    }
}
