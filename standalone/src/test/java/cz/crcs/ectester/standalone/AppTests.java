package cz.crcs.ectester.standalone;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junitpioneer.jupiter.StdIo;
import org.junitpioneer.jupiter.StdOut;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

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

    static Stream<String> libs() {
        return Stream.of("BoringSSL", "Botan", "BouncyCastle", "Crypto++", "IPPCP", "LibreSSL", "libgcrypt", "mbedTLS", "Nettle", "OpenSSL", "SunEC", "tomcrypt", "wolfCrypt");
    }

    @SuppressWarnings("JUnitMalformedDeclaration")
    @ParameterizedTest
    @MethodSource("libs")
    @StdIo()
    public void defaultSuite(String libName, StdOut out) {
        // TODO: "Nettle" is very broken here for a weird reason.
        assumeFalse(libName.equals("Nettle"));

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

    @SuppressWarnings("JUnitMalformedDeclaration")
    @ParameterizedTest
    @MethodSource("libs")
    @StdIo()
    public void testVectorSuite(String libName, StdOut out) {
        String[] args = new String[]{"test", "test-vectors", libName};
        if (libName.equals("Botan") || libName.equals("Crypto++")) {
            args = new String[]{"test", "--kpg-type", "ECDH", "test-vectors", libName};
        }
        ECTesterStandalone.main(args);
        String sout = out.capturedString();
        if (sout.contains("Exception")) {
            System.err.printf("%s: Test vector suite has exceptions.%n", libName);
        }
    }

    @ParameterizedTest
    @MethodSource("libs")
    public void performanceSuite(String libName) {
        // TODO: "Nettle" is very broken here for a weird reason.
        assumeFalse(libName.equals("Nettle"));

        String[] args = new String[]{"test", "performance", libName};
        if (libName.equals("Botan") || libName.equals("Crypto++")) {
            args = new String[]{"test", "--kpg-type", "ECDH", "performance", libName};
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(baos);
        System.setOut(ps);
        ECTesterStandalone.main(args);
        String sout = baos.toString();
        if (sout.contains("Exception")) {
            System.err.printf("%s: Performance suite has exceptions.%n", libName);
        }
    }

    @ParameterizedTest
    @MethodSource("libs")
    public void signatureSuite(String libName) {
        String[] args = new String[]{"test", "signature", libName};
        switch (libName) {
            case "Nettle":
            case "libgcrypt":
            case "BoringSSL":
            case "OpenSSL":
            case "tomcrypt":
            case "LibreSSL":
            case "IPPCP":
            case "mbedTLS":
                args = new String[]{"test", "-st", "NONEwithECDSA", "signature", libName};
                break;
        }
        ECTesterStandalone.main(args);
    }

    @ParameterizedTest
    @MethodSource("libs")
    public void miscSuite(String libName) {
        String[] args = new String[]{"test", "miscellaneous", libName};
        if (libName.equals("Botan") || libName.equals("Crypto++")) {
            args = new String[]{"test", "--kpg-type", "ECDH", "miscellaneous", libName};
        }
        ECTesterStandalone.main(args);
    }

    @ParameterizedTest
    @MethodSource("libs")
    public void invalidSuite(String libName) {
        // TODO: "Nettle" is very broken here for a weird reason.
        assumeFalse(libName.equals("Nettle"));

        String[] args = new String[]{"test", "invalid", libName};
        if (libName.equals("Botan") || libName.equals("Crypto++")) {
            args = new String[]{"test", "--kpg-type", "ECDH", "invalid", libName};
        }
        ECTesterStandalone.main(args);
    }

    @SuppressWarnings("JUnitMalformedDeclaration")
    @ParameterizedTest
    @MethodSource("libs")
    @StdIo()
    public void generate(String libName, StdOut out) {
        String[] args = new String[]{"generate", "-n", "10", "-nc", "secg/secp256r1", libName};
        switch (libName) {
            case "Botan":
            case "Crypto++":
                args = new String[]{"generate", "-n", "10", "-nc", "secg/secp256r1", "-t", "ECDH", libName};
                break;
            case "Nettle":
            case "libgcrypt":
            case "wolfCrypt":
                args = new String[]{"generate", "-n", "10", "-cn", "secp256r1", libName};
                break;
            case "BoringSSL":
                args = new String[]{"generate", "-n", "10", "-cn", "prime256v1", libName};
                break;
        }
        ECTesterStandalone.main(args);
    }

    @SuppressWarnings("JUnitMalformedDeclaration")
    @ParameterizedTest
    @MethodSource("libs")
    @StdIo()
    public void ecdh(String libName, StdOut out) {
        String[] args = new String[]{"ecdh", "-n", "10", "-nc", "secg/secp256r1", libName};
        switch (libName) {
            case "Nettle":
            case "libgcrypt":
            case "wolfCrypt":
                args = new String[]{"ecdh", "-n", "10", "-cn", "secp256r1", libName};
                break;
            case "BoringSSL":
                args = new String[]{"ecdh", "-n", "10", "-cn", "prime256v1", libName};
                break;
        }
        ECTesterStandalone.main(args);
    }

    @SuppressWarnings("JUnitMalformedDeclaration")
    @ParameterizedTest
    @MethodSource("libs")
    @StdIo()
    public void ecdsa(String libName, StdOut out) {
        String[] args = new String[]{"ecdsa", "-n", "10", "-nc", "secg/secp256r1", libName};
        switch (libName) {
            case "Nettle":
            case "libgcrypt":
                args = new String[]{"ecdsa", "-n", "10", "-cn", "secp256r1", "-t", "NONEwithECDSA", libName};
                break;
            case "BoringSSL":
                args = new String[]{"ecdsa", "-n", "10", "-cn", "prime256v1", "-t", "NONEwithECDSA", libName};
                break;
            case "OpenSSL":
            case "tomcrypt":
            case "LibreSSL":
            case "IPPCP":
            case "mbedTLS":
                args = new String[]{"ecdsa", "-n", "10", "-nc", "secg/secp256r1", "-t", "NONEwithECDSA", libName};
                break;
            case "wolfCrypt":
                args = new String[]{"ecdsa", "-n", "10", "-cn", "secp256r1", libName};
                break;
        }
        ECTesterStandalone.main(args);
    }

    @SuppressWarnings("JUnitMalformedDeclaration")
    @ParameterizedTest
    @MethodSource("libs")
    @StdIo()
    public void export(String libName, StdOut out) {
        // TODO: wolfCrypt is weirdly broken here.
        assumeFalse(libName.contains("wolfCrypt"));
        String[] args = new String[]{"export", "-b", "256", libName};
        switch (libName) {
            case "Botan":
            case "Crypto++":
                args = new String[]{"export", "-b", "256", "-t", "ECDH", libName};
                break;
        }
        ECTesterStandalone.main(args);
        System.err.println(out.capturedString());
    }
}
