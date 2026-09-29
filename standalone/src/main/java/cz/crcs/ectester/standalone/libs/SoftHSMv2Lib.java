package cz.crcs.ectester.standalone.libs;

import cz.crcs.ectester.common.util.FileUtil;
import cz.crcs.ectester.standalone.util.PKCS11Config;
import cz.crcs.ectester.standalone.util.PKCS11ConfigWriter;
import cz.crcs.ectester.standalone.util.PKCS11Util;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Objects;

/**
 * Class representing the SoftHSMv2 library.
 *
 * @author Filip Horvath
 */
public abstract class SoftHSMv2Lib extends GenericPKCS11Library {

    private static final String config = "# SoftHSM v2 configuration file\n" +
            "\n" +
            "directories.tokendir = %s\n" +
            "objectstore.backend = file\n" +
            "objectstore.umask = 0077\n" +
            "\n" +
            "# ERROR, WARNING, INFO, DEBUG\n" +
            "log.level = ERROR\n" +
            "\n" +
            "# If CKF_REMOVABLE_DEVICE flag should be set\n" +
            "slots.removable = false\n" +
            "\n" +
            "# Enable and disable PKCS#11 mechanisms using slots.mechanisms.\n" +
            "slots.mechanisms = ALL\n" +
            "\n" +
            "# If the library should reset the state on fork\n" +
            "library.reset_on_fork = false";

    private final Backend backend;

    private String tokenDir;

    private final Path confPath;

    public SoftHSMv2Lib(Backend backend) {
        super("SoftHSMv2-" + backend,
                System.getenv("SOFTHSM2_PIN") != null ? System.getenv("SOFTHSM2_PIN") : "1234");
        this.backend = backend;
        this.confPath = FileUtil.getLibDir().resolve(String.format("SoftHSMv2-%s.conf", this.backend));
    }

    @Override
    public boolean initialize() {
        if (this.isInitialized()) return true;

        if (Objects.equals(
                // if SOFTHSM2_CONF is not set to the variable we want, we assume user set it to his own .conf
                this.confPath.toString(),
                System.getenv("SOFTHSM2_CONF"))
        ) {
            if (!this.initToken()) return false;
        }

        PKCS11Config config;
        try {
            config = PKCS11Config.SoftHSMv2Config(this.backend);
        } catch (IllegalArgumentException e) {
            // happens in case config path was not set and here that can happen only if IOException happened
            return false;
        }

        boolean success = PKCS11ConfigWriter.write(config);
        this.setProviderConfigPath(PKCS11ConfigWriter.getConfigPath());
        return success && super.initialize();
    }

    public static String getResource(Backend backend) {
        return PKCS11Util.getAbsoluteResourcePath(SoftHSMv2Lib.resource(backend));
    }

    private static String resource(Backend backend) {
        return Paths.get("SoftHSMv2",
                String.format("SoftHSMv2-%s", backend),
                "libsofthsm2." + FileUtil.getLibSuffix()).toString();
    }


    private boolean writeConfig() {
        try {
            File config = File.createTempFile(String.format("ECTester-SoftHSMv2-%s",this.backend), ".conf");
            config.deleteOnExit();

            Path symLink = Files.createSymbolicLink(this.confPath, Paths.get(config.getAbsolutePath()));
            symLink.toFile().deleteOnExit();

            return this.writeConfig(config.getAbsolutePath());
        } catch (IOException e) {
            System.err.println(e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    private boolean writeConfig(String path) {
        try (FileWriter fw = new FileWriter(path)) {
            BufferedWriter bw = new BufferedWriter(fw);
            bw.write(String.format(SoftHSMv2Lib.config, this.tokenDir));
            bw.flush();
            return true;
        } catch (Exception e) {
            System.err.println(e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    private boolean initToken() {
        try {
            // create temp directory in which we will store cryptokis
            Path tokenDir = Files.createTempDirectory(String.format("ECTester-SoftHSMv2-%s-Tokens", this.backend));
            tokenDir.toFile().deleteOnExit();
            this.tokenDir = tokenDir.toString();

            // write the softhsm2.conf file with the temp directory as token backend
            if (!this.writeConfig()) return false;

            // create a new process to initialize the token in the tmp directory
            ProcessBuilder pb = new ProcessBuilder("softhsm2-util",
                    "--module", SoftHSMv2Lib.getResource(this.backend), "--init-token", "--label",
                    String.format("ECTester-SoftHSMv2-%s", this.backend),
                    "--slot", "0", "--so-pin", this.getPIN(), "--pin", this.getPIN())
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                    .redirectError(ProcessBuilder.Redirect.INHERIT);

            Process createToken = pb.start();
            int exitStatus = createToken.waitFor();
            if (exitStatus != 0) throw new RuntimeException("Failed to initialize token, stderr from process was inherited.");

            return true;

        } catch (InterruptedException | IOException | RuntimeException e) {
            System.err.println(e);
            System.err.println(e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    public enum Backend {
        OPENSSL,
        BOTAN
    }
}
