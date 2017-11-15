package cz.crcs.ectester.standalone;

import cz.crcs.ectester.common.cli.CLITools;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.standalone.consts.KeyPairGeneratorIdent;
import cz.crcs.ectester.standalone.libs.BouncyCastleLib;
import cz.crcs.ectester.standalone.libs.ECLibrary;
import cz.crcs.ectester.standalone.libs.JavaECLibrary;
import cz.crcs.ectester.standalone.libs.SunECLib;
import org.apache.commons.cli.*;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Standalone part of ECTester, a tool for testing Elliptic curve implementations in software libraries.
 *
 * @author Jan Jancar johny@neuromancer.sk
 * @version v0.1.0
 */
public class ECTesterStandalone {

    private ECLibrary[] libs = new ECLibrary[]{new SunECLib(), new BouncyCastleLib()};
    private EC_Store dataStore;
    private Config cfg;

    private Options opts = new Options();
    private static final String VERSION = "v0.1.0";
    private static final String DESCRIPTION = "ECTesterStandalone " + VERSION + ", an Elliptic Curve Cryptography support tester/utility.";
    private static final String LICENSE = "MIT Licensed\nCopyright (c) 2016-2017 Petr Svenda <petr@svenda.com>";
    private static final String CLI_HEADER = "\n" + DESCRIPTION + "\n\n";
    private static final String CLI_FOOTER = "\n" + LICENSE;

    private void run(String[] args) {
        try {
            CommandLine cli = parseArgs(args);

            if (cli.hasOption("help")) {
                CLITools.help("ECTesterStandalone.jar", CLI_HEADER, opts, CLI_FOOTER, true);
                return;
            } else if (cli.hasOption("version")) {
                CLITools.version(DESCRIPTION, LICENSE);
                return;
            }

            cfg = new Config();
            dataStore = new EC_Store();

            if (cli.hasOption("list-named")) {
                CLITools.listNamed(dataStore, cli.getOptionValue("list-named"));
                return;
            }

            for (ECLibrary lib : libs) {
                if (lib instanceof JavaECLibrary) {
                    JavaECLibrary jlib = (JavaECLibrary) lib;
                    lib.initialize();
                    lib.getECKAs();
                    lib.getECSigs();
                    for (KeyPairGeneratorIdent ident : lib.getKPGs()) {
                        try {
                            KeyPairGenerator kpg = ident.getInstance(jlib.getProvider());
                            kpg.initialize(192);
                            KeyPair kp = kpg.genKeyPair();
                            System.out.println(kp);
                        } catch (NoSuchAlgorithmException e) {
                            e.printStackTrace();
                        }
                    }
                }

            }
            System.out.println(Arrays.toString(libs));

            if (cli.hasOption("generate")) {
                generate();
            } else if (cli.hasOption("list-libs")) {
                listLibraries();
            }

        } catch (ParseException | IOException ex) {
            System.err.println(ex.getMessage());
        }
    }

    private CommandLine parseArgs(String[] args) throws ParseException {
        OptionGroup actions = new OptionGroup();
        actions.setRequired(true);
        actions.addOption(Option.builder("V").longOpt("version").desc("Print version info.").build());
        actions.addOption(Option.builder("h").longOpt("help").desc("Print help.").build());
        actions.addOption(Option.builder("e").longOpt("export").desc("Export the defaut curve parameters of the card(if any).").build());
        actions.addOption(Option.builder("g").longOpt("generate").desc("Generate [amount] of EC keys.").hasArg().argName("amount").optionalArg(true).build());
        actions.addOption(Option.builder("t").longOpt("test").desc("Test ECC support. [test_suite]:\n- default:\n- invalid:\n- wrong:\n- composite:\n- test-vectors:").hasArg().argName("test_suite").optionalArg(true).build());
        actions.addOption(Option.builder("dh").longOpt("ecdh").desc("Do ECDH, [count] times.").hasArg().argName("count").optionalArg(true).build());
        actions.addOption(Option.builder("dhc").longOpt("ecdhc").desc("Do ECDHC, [count] times.").hasArg().argName("count").optionalArg(true).build());
        actions.addOption(Option.builder("dsa").longOpt("ecdsa").desc("Sign data with ECDSA, [count] times.").hasArg().argName("count").optionalArg(true).build());
        actions.addOption(Option.builder("ln").longOpt("list-named").desc("Print the list of supported named curves and keys.").hasArg().argName("what").optionalArg(true).build());
        actions.addOption(Option.builder("ls").longOpt("list-libs").desc("List supported libraries.").build());
        opts.addOptionGroup(actions);

        CommandLineParser parser = new DefaultParser();
        return parser.parse(opts, args);
    }

    /**
     *
     */
    private void generate() {
        EC_Curve curve = dataStore.getObject(EC_Curve.class, "secg/secp192r1");
        byte[] fp = curve.getParam(EC_Consts.PARAMETER_FP)[0];

    }

    /**
     *
     */
    private void listLibraries() {
        for (ECLibrary lib : libs) {
            if (lib.isInitialized()) {
                System.out.println(lib.name());
            }
        }
    }

    public static void main(String[] args) {
        ECTesterStandalone app = new ECTesterStandalone();
        app.run(args);
    }

    public static class Config {

    }
}
