package cz.crcs.ectester.standalone;

import cz.crcs.ectester.common.cli.*;
import cz.crcs.ectester.common.ec.EC_Curve;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.standalone.consts.KeyAgreementIdent;
import cz.crcs.ectester.standalone.consts.KeyPairGeneratorIdent;
import cz.crcs.ectester.standalone.consts.SignatureIdent;
import cz.crcs.ectester.standalone.libs.BouncyCastleLib;
import cz.crcs.ectester.standalone.libs.ECLibrary;
import cz.crcs.ectester.standalone.libs.JavaECLibrary;
import cz.crcs.ectester.standalone.libs.SunECLib;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.*;
import java.util.stream.Collectors;

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
    private TreeCommandLine cli;
    private static final String VERSION = "v0.1.0";
    private static final String DESCRIPTION = "ECTesterStandalone " + VERSION + ", an Elliptic Curve Cryptography support tester/utility.";
    private static final String LICENSE = "MIT Licensed\nCopyright (c) 2016-2017 Petr Svenda <petr@svenda.com>";
    private static final String CLI_HEADER = "\n" + DESCRIPTION + "\n\n";
    private static final String CLI_FOOTER = "\n" + LICENSE;

    private void run(String[] args) {
        try {
            cli = parseArgs(args);

            if (cli.hasOption("help") || cli.getNext() == null) {
                CLITools.help("ECTesterStandalone.jar", CLI_HEADER, opts, optParser, CLI_FOOTER, true);
                return;
            } else if (cli.hasOption("version")) {
                CLITools.version(DESCRIPTION, LICENSE);
                return;
            }


            cfg = new Config(libs);
            if (!cfg.readOptions(cli)) {
                return;
            }
            dataStore = new EC_Store();

            for (ECLibrary lib : libs) {
                lib.initialize();
            }

            if (cli.isNext("list-libs")) {
                listLibraries();
            } else if (cli.isNext("list-data")) {
                CLITools.listNamed(dataStore, cli.getNext().getArg(0));
            } else if (cli.isNext("ecdh")) {
                ecdh();
            } else if (cli.isNext("ecdsa")) {
                ecdsa();
            } else if (cli.isNext("generate")) {
                generate();
            } else if (cli.isNext("test")) {
                test();
            } else if (cli.isNext("export")) {
                export();
            }

        } catch (ParseException | NoSuchAlgorithmException | IOException ex) {
            System.err.println(ex.getMessage());
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
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
        generateOpts.addOption(Option.builder("nc").longOpt("named-curve").desc("Use a named curve, from CurveDB: <cat/id>").hasArg().argName("cat/id").build());
        generateOpts.addOption(Option.builder("n").longOpt("amount").hasArg().argName("amount").optionalArg(false).desc("Generate [amount] of EC keys.").build());
        generateOpts.addOption(Option.builder("t").longOpt("type").hasArg().argName("type").optionalArg(false).desc("Set KeyPairGenerator object [type].").build());
        generateOpts.addOption(Option.builder("b").longOpt("bits").hasArg().argName("n").optionalArg(false).desc("What size of curve to use.").build());
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

        List<Argument> baseArgs = new LinkedList<>();
        baseArgs.add(new Argument("lib", "What library to use.", false));
        optParser = new TreeParser(actions, false, baseArgs);

        opts.addOption(Option.builder("V").longOpt("version").desc("Print version info.").build());
        opts.addOption(Option.builder("h").longOpt("help").desc("Print help.").build());

        return optParser.parse(opts, args);
    }

    /**
     *
     */
    private void listLibraries() {
        for (ECLibrary lib : libs) {
            if (lib.isInitialized() && (cfg.selected == null || lib == cfg.selected)) {
                System.out.println("\t- " + lib.name());
                Set<KeyPairGeneratorIdent> kpgs = lib.getKPGs();
                if (!kpgs.isEmpty()) {
                    System.out.println("\t\t- KeyPairGenerators: " + String.join(",", kpgs.stream().map(KeyPairGeneratorIdent::getName).collect(Collectors.toList())));
                }
                Set<KeyAgreementIdent> eckas = lib.getECKAs();
                if (!eckas.isEmpty()) {
                    System.out.println("\t\t- KeyAgreements: " + String.join(",", eckas.stream().map(KeyAgreementIdent::getName).collect(Collectors.toList())));
                }
                Set<SignatureIdent> sigs = lib.getECSigs();
                if (!eckas.isEmpty()) {
                    System.out.println("\t\t- Signatures: " + String.join(",", sigs.stream().map(SignatureIdent::getName).collect(Collectors.toList())));
                }
            }
        }
    }

    /**
     *
     */
    private void ecdh() {

    }

    /**
     *
     */
    private void ecdsa() {

    }

    /**
     *
     */
    private void generate() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        if (cfg.selected instanceof JavaECLibrary) {
            JavaECLibrary jlib = (JavaECLibrary) cfg.selected;
            KeyPairGeneratorIdent ident = null;
            String algo = cli.getOptionValue("generate.type", "EC");
            for (KeyPairGeneratorIdent kpIdent : jlib.getKPGs()) {
                if (kpIdent.contains(algo)) {
                    ident = kpIdent;
                    break;
                }
            }
            if (ident == null) {
                throw new NoSuchAlgorithmException(algo);
            } else {
                KeyPairGenerator kpg = ident.getInstance(jlib.getProvider());
                if (cli.hasOption("generate.bits")) {
                    int bits = Integer.parseInt(cli.getOptionValue("generate.bits", "256"));
                    kpg.initialize(bits);
                } else if (cli.hasOption("generate.named-curve")) {
                    String curveName = cli.getOptionValue("generate.named-curve");
                    EC_Curve curve = dataStore.getObject(EC_Curve.class, curveName);
                    if (curve == null) {
                        System.err.println("Curve not found: " + curveName);
                        return;
                    }
                    kpg.initialize(curve.toSpec());
                } else {
                    kpg.initialize(256);
                }

                int amount = Integer.parseInt(cli.getOptionValue("generate.amount", "1"));
                for (int i = 0; i < amount; ++i) {
                    KeyPair kp = kpg.genKeyPair();
                    ECPrivateKey privateKey = (ECPrivateKey) kp.getPrivate();
                    ECPublicKey publicKey = (ECPublicKey) kp.getPublic();
                    System.out.println(privateKey);
                }
            }
        }
    }

    /**
     *
     */
    private void test() {

    }

    /**
     *
     */
    private void export() {

    }

    public static void main(String[] args) {
        ECTesterStandalone app = new ECTesterStandalone();
        app.run(args);
    }


    /**
     *
     */
    public static class Config {
        private ECLibrary[] libs;
        public ECLibrary selected = null;

        public Config(ECLibrary[] libs) {
            this.libs = libs;
        }

        boolean readOptions(TreeCommandLine cli) {
            if (cli.isNext("generate")) {
                if (!cli.hasArg(-1)) {
                    System.err.println("Missing library name argument.");
                    return false;
                }

                if (cli.hasOption("generate.bits") && cli.hasOption("generate.named-curve")) {
                    System.err.println("");
                    return false;
                }
            }

            String libraryName = cli.getArg(-1);
            if (libraryName != null) {
                List<ECLibrary> matchedLibs = new LinkedList<>();
                for (ECLibrary lib : libs) {
                    if (lib.name().toLowerCase().contains(libraryName.toLowerCase())) {
                        matchedLibs.add(lib);
                    }
                }
                if (matchedLibs.size() == 0) {
                    System.err.println("No library " + libraryName + " found.");
                    return false;
                } else if (matchedLibs.size() > 1) {
                    System.err.println("Multiple matching libraries found: " + String.join(",", matchedLibs.stream().map(ECLibrary::name).collect(Collectors.toList())));
                    return false;
                } else {
                    selected = matchedLibs.get(0);
                }
            }

            return true;
        }
    }
}
