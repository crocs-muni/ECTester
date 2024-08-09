package cz.crcs.ectester.standalone;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junitpioneer.jupiter.StdIo;
import org.junitpioneer.jupiter.StdOut;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DeterministicTests {

    static Stream<String> libs() {
        return Stream.of("Botan", "BouncyCastle", "Crypto++", "IPPCP", "mbedTLS", "Nettle", "OpenSSL", "SunEC", "tomcrypt");
        // BoringSSL and libgcrypt cannot be easily tested here, because they initialize their RNG only once per process.
        // LibreSSL hangs in CI.
    }

    @SuppressWarnings("JUnitMalformedDeclaration")
    @ParameterizedTest
    @MethodSource("libs")
    @StdIo()
    public void generate(String libName, StdOut out) {
        String[] args = new String[]{"generate", "-ps", "123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234", "-n", "10", "-nc", "secg/secp256r1", libName};
        switch (libName) {
            case "Botan":
                args = new String[]{"generate", "-ps", "123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234", "-n", "10", "-nc", "secg/secp256r1", "-t", "ECDH", libName};
                break;
            case "Crypto++":
                args = new String[]{"generate", "-ps", "12345678", "-n", "10", "-nc", "secg/secp256r1", "-t", "ECDH", libName};
                break;
            case "Nettle":
                args = new String[]{"generate", "-ps", "123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234", "-n", "10", "-cn", "secp256r1", libName};
                break;
            case "mbedTLS":
                args = new String[]{"generate", "-ps", "12345678", "-n", "10", "-nc", "secg/secp256r1", libName};
                break;
        }
        ECTesterStandalone.main(args);
        String out1 = out.capturedString();
        ECTesterStandalone.main(args);
        String out2 = out.capturedString().substring(out1.length());
        if (!out1.contains(";"))
            return;
        List<String> lines1 = out1.lines().collect(Collectors.toList());
        List<String> lines2 = out2.lines().collect(Collectors.toList());
        assertEquals(lines1.size(), lines2.size());
        for (int i = 0; i < lines1.size(); ++i) {
            String[] parts1 = lines1.get(i).split(";");
            String[] parts2 = lines2.get(i).split(";");
            assertEquals(parts1[2], parts2[2]);
            assertEquals(parts1[3], parts2[3]);
        }
    }

    @SuppressWarnings("JUnitMalformedDeclaration")
    @ParameterizedTest
    @MethodSource("libs")
    @StdIo()
    public void ecdh(String libName, StdOut out) {
        String[] args = new String[]{"ecdh", "-ps", "123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234", "-n", "10", "-nc", "secg/secp256r1", libName};
        switch (libName) {
            case "Nettle":
                args = new String[]{"ecdh", "-ps", "123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234", "-n", "10", "-cn", "secp256r1", libName};
                break;
            case "Crypto++":
                args = new String[]{"ecdh", "-ps", "12345678", "-n", "10", "-nc", "secg/secp256r1", "-t", "ECDH", libName};
                break;
            case "mbedTLS":
                args = new String[]{"ecdh", "-ps", "12345678", "-n", "10", "-nc", "secg/secp256r1", libName};
                break;
        }
        ECTesterStandalone.main(args);
        String out1 = out.capturedString();
        ECTesterStandalone.main(args);
        String out2 = out.capturedString().substring(out1.length());
        if (!out1.contains(";"))
            return;
        List<String> lines1 = out1.lines().collect(Collectors.toList());
        List<String> lines2 = out2.lines().collect(Collectors.toList());
        assertEquals(lines1.size(), lines2.size());
        for (int i = 0; i < lines1.size(); ++i) {
            String[] parts1 = lines1.get(i).split(";");
            String[] parts2 = lines2.get(i).split(";");
            assertEquals(parts1[2], parts2[2]); // pubkey
            assertEquals(parts1[3], parts2[3]); // privkey
            assertEquals(parts1[4], parts2[4]); // secret
        }
    }

    @SuppressWarnings("JUnitMalformedDeclaration")
    @ParameterizedTest
    @MethodSource("libs")
    @StdIo()
    public void ecdsa(String libName, StdOut out) {
        String[] args = new String[]{"ecdsa", "-ps", "123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234", "-d", "1234", "-n", "10", "-nc", "secg/secp256r1", libName};
        switch (libName) {
            case "Nettle":
                args = new String[]{"ecdsa", "-ps", "123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234", "-d", "1234", "-n", "10", "-cn", "secp256r1", "-t", "NONEwithECDSA", libName};
                break;
            case "OpenSSL":
            case "tomcrypt":
                args = new String[]{"ecdsa", "-ps", "123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234", "-d", "1234", "-n", "10", "-nc", "secg/secp256r1", "-t", "NONEwithECDSA", libName};
                break;
            case "IPPCP":
                // TODO: Weird, IPPCP cannot sign less than 4 bytes.
                args = new String[]{"ecdsa", "-ps", "123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234", "-d", "12345678", "-n", "10", "-nc", "secg/secp256r1", "-t", "NONEwithECDSA", libName};
                break;
            case "Crypto++":
                args = new String[]{"ecdsa", "-ps", "12345678", "-d", "1234", "-n", "10", "-nc", "secg/secp256r1", "-t", "ECDSA", libName};
                break;
            case "LibreSSL":
            case "mbedTLS":
                args = new String[]{"ecdsa", "-ps", "12345678", "-d", "1234", "-n", "10", "-nc", "secg/secp256r1", "-t", "NONEwithECDSA", libName};
                break;
        }
        ECTesterStandalone.main(args);
        String out1 = out.capturedString();
        ECTesterStandalone.main(args);
        String out2 = out.capturedString().substring(out1.length());
        if (!out1.contains(";"))
            return;
        List<String> lines1 = out1.lines().collect(Collectors.toList());
        List<String> lines2 = out2.lines().collect(Collectors.toList());
        assertEquals(lines1.size(), lines2.size());
        for (int i = 0; i < lines1.size(); ++i) {
            String[] parts1 = lines1.get(i).split(";");
            String[] parts2 = lines2.get(i).split(";");
            assertEquals(parts1[3], parts2[3]); // data
            assertEquals(parts1[4], parts2[4]); // pubkey
            assertEquals(parts1[5], parts2[5]); // privkey
            assertEquals(parts1[6], parts2[6]); // signature
            assertEquals(parts1[7], parts2[7]); // nonce
        }
    }
}
