package cz.crcs.ectester.standalone;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junitpioneer.jupiter.StdIo;
import org.junitpioneer.jupiter.StdOut;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
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

    String[] buildCLIArgs(String libName, String suite, String... additional) {
        String resultPath = System.getenv("RESULT_PATH");
        List<String> args = new LinkedList<>();
        args.add("test");
        if (resultPath != null) {
            File resultDir = new File(resultPath);
            if (resultDir.exists() || resultDir.mkdirs()) {
                args.add("-o");
                args.add(String.format("text:%s/%s_%s.txt", resultPath, suite, libName));
                args.add("-o");
                args.add(String.format("yaml:%s/%s_%s.yml", resultPath, suite, libName));
                args.add("-o");
                args.add(String.format("xml:%s/%s_%s.xml", resultPath, suite, libName));
            }
        }
        Collections.addAll(args, additional);
        args.add(suite);
        args.add(libName);
        return args.toArray(new String[]{});
    }

    @SuppressWarnings("JUnitMalformedDeclaration")
    @ParameterizedTest
    @MethodSource("libs")
    @StdIo()
    public void defaultSuite(String libName, StdOut out) {
        // TODO: "Nettle" is very broken here for a weird reason.
        assumeFalse(libName.equals("Nettle"));

        String[] args = buildCLIArgs(libName, "default");
        if (libName.equals("Botan") || libName.equals("Crypto++")) {
            args = buildCLIArgs(libName, "default", "--kpg-type", "ECDH");
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
        String[] args = buildCLIArgs(libName, "test-vectors");
        if (libName.equals("Botan") || libName.equals("Crypto++")) {
            args = buildCLIArgs(libName, "test-vectors", "--kpg-type", "ECDH");
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

        String[] args = buildCLIArgs(libName, "performance");
        if (libName.equals("Botan") || libName.equals("Crypto++")) {
            args = buildCLIArgs(libName, "performance", "--kpg-type", "ECDH");
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
        String[] args = buildCLIArgs(libName, "signature", "-q");
        switch (libName) {
            case "Nettle":
            case "libgcrypt":
            case "BoringSSL":
            case "OpenSSL":
            case "tomcrypt":
            case "LibreSSL":
            case "IPPCP":
            case "mbedTLS":
                args = buildCLIArgs(libName, "signature", "-st", "NONEwithECDSA", "-q");
                break;
        }
        ECTesterStandalone.main(args);
    }

    @ParameterizedTest
    @MethodSource("libs")
    @Timeout(20)
    public void miscSuite(String libName) {
        String[] args = buildCLIArgs(libName, "miscellaneous", "-q");
        if (libName.equals("Botan") || libName.equals("Crypto++")) {
            args = buildCLIArgs(libName, "miscellaneous", "--kpg-type", "ECDH", "-q");
        }
        ECTesterStandalone.main(args);
    }

    @ParameterizedTest
    @MethodSource("libs")
    @Timeout(20)
    public void twistSuite(String libName) {
        // TODO: "Nettle" is very broken here for a weird reason.
        assumeFalse(libName.equals("Nettle"));

        String[] args = buildCLIArgs(libName, "twist", "-q");
        if (libName.equals("Botan") || libName.equals("Crypto++")) {
            args = buildCLIArgs(libName, "twist", "--kpg-type", "ECDH", "-q");
        }
        ECTesterStandalone.main(args);
    }

    @ParameterizedTest
    @MethodSource("libs")
    @Timeout(20)
    public void degenerateSuite(String libName) {
        // TODO: "Nettle" is very broken here for a weird reason.
        assumeFalse(libName.equals("Nettle"));

        String[] args = buildCLIArgs(libName, "degenerate", "-q");
        if (libName.equals("Botan") || libName.equals("Crypto++")) {
            args = buildCLIArgs(libName, "degenerate", "--kpg-type", "ECDH", "-q");
        }
        ECTesterStandalone.main(args);
    }

    @ParameterizedTest
    @MethodSource("libs")
    @Timeout(20)
    public void edgeCasesSuite(String libName) {
        // TODO: Crypto++ and tomcrypt is broken here.
        assumeFalse(libName.equals("Crypto++") || libName.equals("tomcrypt"));

        String[] args = buildCLIArgs(libName, "edge-cases", "-q");
        if (libName.equals("Botan") || libName.equals("Crypto++")) {
            args = buildCLIArgs(libName, "edge-cases", "--kpg-type", "ECDH", "-q");
        }
        ECTesterStandalone.main(args);
    }

    @ParameterizedTest
    @MethodSource("libs")
    @Timeout(20)
    // TODO: This breaks the tests because the libs do all sorts of weird stuff here.
    @Disabled
    public void compositeSuite(String libName) {
        // TODO: "Crypto++" and IPPCP cycles indefinitely here.
        assumeFalse(libName.equals("Crypto++") || libName.equals("IPPCP") || libName.equals("OpenSSL"));

        String[] args = buildCLIArgs(libName, "composite", "-q");
        if (libName.equals("Botan") || libName.equals("Crypto++")) {
            args = buildCLIArgs(libName, "composite", "--kpg-type", "ECDH", "-q");
        }
        ECTesterStandalone.main(args);
    }

    @ParameterizedTest
    @MethodSource("libs")
    @Timeout(20)
    public void cofactorSuite(String libName) {
        String[] args = buildCLIArgs(libName, "cofactor", "-q");
        if (libName.equals("Botan") || libName.equals("Crypto++")) {
            args = buildCLIArgs(libName, "cofactor", "--kpg-type", "ECDH", "-q");
        }
        ECTesterStandalone.main(args);
    }

    @ParameterizedTest
    @MethodSource("libs")
    @Timeout(20)
    // TODO: This breaks the tests because the libs do all sorts of weird stuff here.
    @Disabled
    public void wrongSuite(String libName) {
        // TODO: "BouncyCastle" and Crypto++ cycles indefinitely here.
        assumeFalse(libName.equals("BouncyCastle") || libName.equals("Crypto++") || libName.equals("IPPCP") || libName.equals("wolfCrypt"));

        String[] args = buildCLIArgs(libName, "wrong", "-q");
        if (libName.equals("Botan") || libName.equals("Crypto++")) {
            args = buildCLIArgs(libName, "wrong", "--kpg-type", "ECDH", "-q");
        }
        ECTesterStandalone.main(args);
    }

    @ParameterizedTest
    @MethodSource("libs")
    @Timeout(20)
    public void invalidSuite(String libName) {
        // TODO: "Nettle" is very broken here for a weird reason.
        assumeFalse(libName.equals("Nettle"));

        String[] args = buildCLIArgs(libName, "invalid", "-q");
        if (libName.equals("Botan") || libName.equals("Crypto++")) {
            args = buildCLIArgs(libName, "invalid", "--kpg-type", "ECDH", "-q");
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
