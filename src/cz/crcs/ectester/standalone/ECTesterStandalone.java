package cz.crcs.ectester.standalone;

import cz.crcs.ectester.common.Util;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.data.EC_Store;
import org.apache.commons.cli.*;

import java.io.IOException;

/**
 * Standalone part of ECTester, a tool for testing Elliptic curve implementations in software libraries.
 *
 * @author Jan Jancar johny@neuromancer.sk
 * @version v0.1.0
 */
public class ECTesterStandalone {

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
                help();
                return;
            } else if (cli.hasOption("version")) {
                version();
                return;
            }

            cfg = new Config();
            dataStore = new EC_Store();

            if (cli.hasOption("generate")) {
                generate();
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
        actions.addOption(Option.builder("g").longOpt("generate").desc("Generate [amount] of EC keys.").hasArg().argName("amount").optionalArg(true).build());
        opts.addOptionGroup(actions);

        CommandLineParser parser = new DefaultParser();
        return parser.parse(opts, args);
    }

    /**
     * Prints help.
     */
    private void help() {
        HelpFormatter help = new HelpFormatter();
        help.setOptionComparator(null);
        help.printHelp("ECTesterStandalone.jar", CLI_HEADER, opts, CLI_FOOTER, true);
    }

    /**
     * Prints version info.
     */
    private void version() {
        System.out.println(DESCRIPTION);
        System.out.println(LICENSE);
    }

    /**
     *
     */
    private void generate() {
        EC_Curve curve = dataStore.getObject(EC_Curve.class, "secg/secp192r1");
        byte[] fp = curve.getParam(EC_Consts.PARAMETER_FP)[0];

    }

    public static void main(String[] args) {
        ECTesterStandalone app = new ECTesterStandalone();
        app.run(args);
    }

    public static class Config {

    }
}
