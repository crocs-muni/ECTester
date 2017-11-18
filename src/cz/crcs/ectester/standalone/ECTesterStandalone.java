package cz.crcs.ectester.standalone;

import cz.crcs.ectester.common.cli.*;
import cz.crcs.ectester.common.test.Result;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.standalone.consts.KeyPairGeneratorIdent;
import cz.crcs.ectester.standalone.libs.BouncyCastleLib;
import cz.crcs.ectester.standalone.libs.ECLibrary;
import cz.crcs.ectester.standalone.libs.JavaECLibrary;
import cz.crcs.ectester.standalone.libs.SunECLib;
import cz.crcs.ectester.standalone.test.KeyGenerationTest;
import cz.crcs.ectester.standalone.test.KeyGenerationTestable;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.IOException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.*;

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
    private TreeParser optParser;
    private static final String VERSION = "v0.1.0";
    private static final String DESCRIPTION = "ECTesterStandalone " + VERSION + ", an Elliptic Curve Cryptography support tester/utility.";
    private static final String LICENSE = "MIT Licensed\nCopyright (c) 2016-2017 Petr Svenda <petr@svenda.com>";
    private static final String CLI_HEADER = "\n" + DESCRIPTION + "\n\n";
    private static final String CLI_FOOTER = "\n" + LICENSE;

    private void run(String[] args) {
        try {
            TreeCommandLine cli = parseArgs(args);

            if (cli.hasOption("help")) {
                CLITools.help("ECTesterStandalone.jar", CLI_HEADER, opts, optParser, CLI_FOOTER, true);
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
                lib.initialize();
            }

            if (cli.isNext("list-libs")) {
                listLibraries();
            } else if (cli.isNext("list-data")) {
                CLITools.listNamed(dataStore, cli.getNext().getArg(0));
            } else if (cli.isNext("ecdh")) {

            } else if (cli.isNext("ecdsa")) {

            } else if (cli.isNext("generate")) {
                generate();
            } else if (cli.isNext("test")) {

            } else if (cli.isNext("export")) {

            }

        } catch (ParseException | IOException ex) {
            System.err.println(ex.getMessage());
        }
    }

    private TreeCommandLine parseArgs(String[] args) throws ParseException {
        Map<String, ParserOptions> actions = new TreeMap<>();

        Options testOpts = new Options();
        ParserOptions test = new ParserOptions(new DefaultParser(), testOpts);
        actions.put("test", test);

        Options ecdhOpts = new Options();
        ecdhOpts.addOption(Option.builder("t").longOpt("type").desc("Set KeyAgreement object [type].").hasArg().argName("type").optionalArg(false).build());
        ParserOptions ecdh = new ParserOptions(new DefaultParser(), ecdhOpts);
        actions.put("ecdh", ecdh);

        Options ecdsaOpts = new Options();
        ecdsaOpts.addOption(Option.builder("t").longOpt("type").desc("Set Signature object [type].").hasArg().argName("type").optionalArg(false).build());
        ParserOptions ecdsa = new ParserOptions(new DefaultParser(), ecdsaOpts);
        actions.put("ecdsa", ecdsa);

        Options generateOpts = new Options();
        generateOpts.addOption(Option.builder("n").longOpt("amount").hasArg().argName("amount").optionalArg(false).desc("Generate [amount] of EC keys.").build());
        ParserOptions generate = new ParserOptions(new DefaultParser(), generateOpts);
        actions.put("generate", generate);

        Options exportOpts = new Options();
        ParserOptions export = new ParserOptions(new DefaultParser(), exportOpts);
        actions.put("export", export);

        Options listDataOpts = new Options();
        List<Argument> listDataArgs = new LinkedList<>();
        listDataArgs.add(new Argument("what", "what to list.", false));
        ParserOptions listData = new ParserOptions(new TreeParser(Collections.emptyMap(), false, listDataArgs), listDataOpts);
        actions.put("list-data", listData);

        Options listLibsOpts = new Options();
        ParserOptions listLibs = new ParserOptions(new DefaultParser(), listLibsOpts);
        actions.put("list-libs", listLibs);

        optParser = new TreeParser(actions, false);

        opts.addOption(Option.builder("V").longOpt("version").desc("Print version info.").build());
        opts.addOption(Option.builder("h").longOpt("help").desc("Print help.").build());

        return optParser.parse(opts, args);
    }

    /**
     *
     */
    private void generate() {
        for (ECLibrary lib : libs) {
            if (lib instanceof JavaECLibrary) {
                JavaECLibrary jlib = (JavaECLibrary) lib;
                for (KeyPairGeneratorIdent ident : lib.getKPGs()) {
                    try {
                        KeyPairGenerator kpg = ident.getInstance(jlib.getProvider());
                        KeyGenerationTestable kgt = new KeyGenerationTestable(kpg, 192);
                        KeyGenerationTest kt = KeyGenerationTest.expect(kgt, Result.ExpectedValue.SUCCESS);
                        System.out.println(kt);
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
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
