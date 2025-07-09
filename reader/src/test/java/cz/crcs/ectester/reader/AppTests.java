package cz.crcs.ectester.reader;

import org.junit.jupiter.api.Disabled;
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

    @Test
    @XFail(value = "JCardSim sometimes times-out.")
    @StdIo()
    public void defaultSuite(StdOut out) {
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> ECTesterReader.main(new String[]{"-t", "default", "-s"}));
    }

    @Test
    @XFail(value = "JCardSim sometimes times-out.")
    @StdIo()
    public void defaultSuitePart(StdOut out) {
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> ECTesterReader.main(new String[]{"-t", "default:3:5", "-s"}));
    }

    @Test
    @XFail(value = "JCardSim sometimes times-out.")
    @Disabled
    @StdIo()
    public void testVectorSuite(StdOut out) {
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> ECTesterReader.main(new String[]{"-t", "test-vectors", "-s"}));
    }

    @Test
    @XFail(value = "JCardSim sometimes times-out.")
    @StdIo()
    public void compressionSuite(StdOut out) {
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> ECTesterReader.main(new String[]{"-t", "compression", "-s"}));
    }

    @Test
    @XFail(value = "JCardSim sometimes times-out.")
    @Disabled
    @StdIo()
    public void wrongSuite(StdOut out) {
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> ECTesterReader.main(new String[]{"-t", "wrong", "-s", "-y"}));
    }

    @Test
    @XFail(value = "JCardSim sometimes times-out.")
    @StdIo()
    public void degenerateSuite(StdOut out) {
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> ECTesterReader.main(new String[]{"-t", "degenerate", "-s", "-y"}));
    }

    @Test
    @XFail(value = "JCardSim sometimes times-out.")
    @Disabled
    @StdIo()
    public void cofactorSuite(StdOut out) {
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> ECTesterReader.main(new String[]{"-t", "cofactor", "-s", "-y"}));
    }

    @Test
    @XFail(value = "JCardSim sometimes times-out.")
    @Disabled
    @StdIo()
    public void compositeSuite(StdOut out) {
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> ECTesterReader.main(new String[]{"-t", "composite", "-s", "-y"}));
    }

    @Test
    @XFail(value = "JCardSim sometimes times-out.")
    @StdIo()
    public void invalidSuite(StdOut out) {
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> ECTesterReader.main(new String[]{"-t", "invalid", "-s", "-y"}));
    }

    @Test
    @XFail(value = "JCardSim sometimes times-out.")
    @StdIo()
    public void edgeCasesSuite(StdOut out) {
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> ECTesterReader.main(new String[]{"-t", "edge-cases", "-s", "-y"}));
    }

    @Test
    @XFail(value = "JCardSim sometimes times-out.")
    @StdIo()
    public void signatureSuite(StdOut out) {
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> ECTesterReader.main(new String[]{"-t", "signature", "-s"}));
    }

    @Test
    @XFail(value = "JCardSim sometimes times-out.")
    @StdIo()
    public void twistSuite(StdOut out) {
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> ECTesterReader.main(new String[]{"-t", "twist", "-s", "-y"}));
    }

    @Test
    @XFail(value = "JCardSim sometimes times-out.")
    @StdIo()
    public void miscellaneousSuite(StdOut out) {
        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> ECTesterReader.main(new String[]{"-t", "miscellaneous", "-s", "-y"}));
    }

    @Test
    public void generate() {
        ECTesterReader.main(new String[]{"-g", "10", "-s", "-fp", "-o", "/dev/null", "-b", "256"});
    }

    @Test
    @StdIo()
    public void ecdh(StdOut out) {
        ECTesterReader.main(new String[]{"-dh", "-fp", "-b", "256", "-s"});
        String s = out.capturedString();
        assertTrue(s.contains("OK"));
        assertTrue(s.contains("ALG_EC_SVDP_DH of remote pubkey and local privkey"));
    }

    @Test
    @StdIo()
    public void ecdh_external(StdOut out) {
        ECTesterReader.main(new String[]{"-dh", "-fp", "--external", "--named-curve", "secg/secp256r1", "--named-public", "invalid/secp256r1/0", "-b", "256", "-s"});
        String s = out.capturedString();
        assertTrue(s.contains("OK"));
        assertTrue(s.contains("ALG_EC_SVDP_DH of external pubkey and local privkey"));
    }

    @Test
    @StdIo()
    public void ecdsa(StdOut out) {
        ECTesterReader.main(new String[]{"-dsa", "-fp", "-b", "256", "-s"});
        String s = out.capturedString();
        System.err.println(s);
    }

    @Test
    @StdIo()
    public void export(StdOut out) {
        ECTesterReader.main(new String[]{"-e", "-fp", "-b", "256", "-s", "-o", "/dev/null"});
    }

    @Test
    @StdIo()
    public void info(StdOut out) {
        ECTesterReader.main(new String[]{"-nf", "-s"});
    }
}
