package cz.crcs.ectester.standalone;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junitpioneer.jupiter.ExpectedToFail;
import org.junitpioneer.jupiter.StdErr;
import org.junitpioneer.jupiter.StdIo;
import org.junitpioneer.jupiter.StdOut;

import static org.junit.jupiter.api.Assertions.*;

public class AppTests {

    @Test
    @StdIo()
    public void help(StdOut out) {
        ECTesterStandalone.main(new String[]{"-h"});
        String s = out.capturedString();
        assertTrue(s.contains("ECTesterStandalone"));
    }

    @Test
    @StdIo()
    public void listLibraries(StdOut out) {
        ECTesterStandalone.main(new String[]{"list-libs"});
        String s = out.capturedString();
        assertTrue(s.contains("BouncyCastle"));
    }

    @Test
    @StdIo()
    public void listData(StdOut out) {
        ECTesterStandalone.main(new String[]{"list-data"});
        String s = out.capturedString();
        assertTrue(s.contains("secg"));
    }

    @Test
    @StdIo()
    public void listSuites(StdOut out) {
        ECTesterStandalone.main(new String[]{"list-suites"});
        String s = out.capturedString();
        assertTrue(s.contains("default test suite"));
    }

    @Test
    @StdIo()
    public void listIdents(StdOut out) {
        ECTesterStandalone.main(new String[]{"list-types"});
        String s = out.capturedString();
        assertTrue(s.contains("NONEwithECDSA"));
    }

    @SuppressWarnings("JUnitMalformedDeclaration")
    @ParameterizedTest
    // TODO: @ExpectedToFail does not work with parameterized tests: https://github.com/junit-pioneer/junit-pioneer/issues/762
    @ExpectedToFail
    @ValueSource(strings = {"Bouncy", "Sun", "libtomcrypt", "Botan", "Crypto++", "OpenSSL 3", "BoringSSL", "libgcrypt", "mbed TLS", "2021" /* IPPCP */, "Nettle", "LibreSSL", "wolfCrypt"})
    @StdIo()
    public void defaultSuite(String libName, StdOut out) {
        String[] args = new String[]{"test", "default", libName};
        if (libName.equals("Botan") || libName.equals("Crypto++")) {
            args = new String[]{"test", "--kpg-type", "ECDH", "default", libName};
        }
        ECTesterStandalone.main(args);
        String sout = out.capturedString();
        if (sout.contains("Exception")) {
            System.err.printf("%s: Default suite has exceptions.%n", libName);
        }
    }
}
