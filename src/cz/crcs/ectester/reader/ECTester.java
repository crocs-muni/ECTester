/*
 * Copyright (c) 2016-2017 Petr Svenda <petr@svenda.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package cz.crcs.ectester.reader;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.ec.*;
import javacard.security.KeyPair;
import org.apache.commons.cli.*;

import javax.smartcardio.CardException;
import java.io.*;
import java.nio.file.Files;
import java.util.*;

/**
 * Reader part of ECTester, a tool for testing Elliptic curve support on javacards.
 *
 * @author Petr Svenda petr@svenda.com
 * @author Jan Jancar johny@neuromancer.sk
 */
public class ECTester {

    private CardMngr cardManager;
    private DirtyLogger systemOutLogger;
    private EC_Store dataStore;

    //Options
    private int optBits;
    private boolean optAll;
    private boolean optPrimeField = false;
    private boolean optBinaryField = false;

    private String optNamedCurve = null;
    private String optCurveFile = null;
    private boolean optCustomCurve = false;

    private boolean optAnyPublic = false;
    private String optNamedPublic = null;
    private String optPublic = null;

    private boolean optAnyPrivate = false;
    private String optNamedPrivate = null;
    private String optPrivate = null;

    private boolean optAnyKey = false;
    private String optNamedKey = null;
    private String optKey = null;

    private boolean optAnyKeypart = false;

    private String optLog = null;

    private boolean optVerbose = false;
    private String optInput = null;
    private String optOutput = null;
    private boolean optFresh = false;
    private boolean optSimulate = false;

    //Action-related options
    private String optListNamed;
    private String optTestSuite;
    private int optGenerateAmount;
    private int optECDHCount;
    private byte optECDHKA;
    private int optECDSACount;


    private Options opts = new Options();
    private static final String CLI_HEADER = "\nECTester, a javacard Elliptic Curve Cryptograhy support tester/utility.\n\n";
    private static final String CLI_FOOTER = "\nMIT Licensed\nCopyright (c) 2016-2017 Petr Svenda <petr@svenda.com>";

    private static final byte[] SELECT_ECTESTERAPPLET = {(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0a,
            (byte) 0x45, (byte) 0x43, (byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x65, (byte) 0x72, (byte) 0x30, (byte) 0x31};
    private static final byte[] AID = {(byte) 0x45, (byte) 0x43, (byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x65, (byte) 0x72, (byte) 0x30, (byte) 0x31};
    private static final byte[] INSTALL_DATA = new byte[10];

    private void run(String[] args) {
        try {
            CommandLine cli = parseArgs(args);

            //if help, print and quit
            if (cli.hasOption("help")) {
                help();
                return;
            }
            //if not, read other options first, into attributes, then do action
            if (!readOptions(cli)) {
                return;
            }

            dataStore = new EC_Store();
            //if list, print and quit
            if (cli.hasOption("list-named")) {
                list();
                return;
            }

            //init CardManager
            cardManager = new CardMngr(optVerbose, optSimulate);

            //connect or simulate connection
            if (optSimulate) {
                if (!cardManager.prepareLocalSimulatorApplet(AID, INSTALL_DATA, ECTesterApplet.class)) {
                    System.err.println("Failed to establish a simulator.");
                    System.exit(1);
                }
            } else {
                if (!cardManager.connectToCardSelect()) {
                    System.err.println("Failed to connect to card.");
                    System.exit(1);
                }
                cardManager.send(SELECT_ECTESTERAPPLET);
            }

            systemOutLogger = new DirtyLogger(optLog, true);

            //do action
            if (cli.hasOption("export")) {
                export();
            } else if (cli.hasOption("generate")) {
                generate();
            } else if (cli.hasOption("test")) {
                test();
            } else if (cli.hasOption("ecdh") || cli.hasOption("ecdhc")) {
                ecdh();
            } else if (cli.hasOption("ecdsa")) {
                ecdsa();
            }

            //disconnect
            cardManager.disconnectFromCard();
            systemOutLogger.close();

        } catch (MissingOptionException moex) {
            System.err.println("Missing required options, one of:");
            for (Object opt : moex.getMissingOptions().toArray()) {
                if (opt instanceof OptionGroup) {
                    for (Option o : ((OptionGroup) opt).getOptions()) {
                        System.err.print("-" + o.getOpt());

                        if (o.hasLongOpt()) {
                            System.err.print("\t/ --" + o.getLongOpt() + " ");
                        }

                        if (o.hasArg()) {
                            if (o.hasOptionalArg()) {
                                System.err.print("[" + o.getArgName() + "] ");
                            } else {
                                System.err.print("<" + o.getArgName() + "> ");
                            }
                        }

                        if (o.getDescription() != null) {
                            System.err.print("\t\t\t" + o.getDescription());
                        }
                        System.err.println();
                    }
                } else if (opt instanceof String) {
                    System.err.println(opt);
                }
            }
        } catch (MissingArgumentException maex) {
            System.err.println("Option, " + maex.getOption().getOpt() + " requires an argument: " + maex.getOption().getArgName());
        } catch (NumberFormatException nfex) {
            System.err.println("Not a number. " + nfex.getMessage());
        } catch (FileNotFoundException fnfe) {
            System.err.println("File " + fnfe.getMessage() + " not found.");
        } catch (ParseException | IOException | CardException ex) {
            System.err.println(ex.getMessage());
        }
    }

    /**
     * Parses command-line options.
     *
     * @param args cli arguments
     * @return parsed CommandLine object
     * @throws ParseException if there are any problems encountered while parsing the command line tokens
     */
    private CommandLine parseArgs(String[] args) throws ParseException {
        /*
         * Actions:
         * -h / --help
         * -e / --export
         * -g / --generate [amount]
         * -t / --test [test_suite]
         * -dh / --ecdh [count]
         * -dhc / --ecdhc [count]
         * -dsa / --ecdsa [count]
         * -ln / --list-named
         *
         * Options:
         * -b / --bit-size <b> // -a / --all
         *
         * -fp / --prime-field
         * -f2m / --binary-field
         *
         * -u / --custom
         * -nc / --named-curve <cat/id>
         * -c / --curve <curve_file> field,a,b,gx,gy,r,k
         *
         * -pub / --public <pubkey_file> wx,wy
         * -npub / --named-public <cat/id>
         *
         * -priv / --private <privkey_file> s
         * -npriv / --named-private <cat/id>
         *
         * -k / --key <key_file> wx,wy,s
         * -nk / --named-key <cat/id>
         *
         * -v / --verbose
         *
         * -i / --input <input_file>
         * -o / --output <output_file>
         * -l / --log [log_file]
         *
         * -f / --fresh
         * -s / --simulate
         */
        OptionGroup actions = new OptionGroup();
        actions.setRequired(true);
        actions.addOption(Option.builder("h").longOpt("help").desc("Print help.").build());
        actions.addOption(Option.builder("ln").longOpt("list-named").desc("Print the list of supported named curves and keys.").hasArg().argName("what").optionalArg(true).build());
        actions.addOption(Option.builder("e").longOpt("export").desc("Export the defaut curve parameters of the card(if any).").build());
        actions.addOption(Option.builder("g").longOpt("generate").desc("Generate [amount] of EC keys.").hasArg().argName("amount").optionalArg(true).build());
        actions.addOption(Option.builder("t").longOpt("test").desc("Test ECC support. [test_suite]:\n- default:\n- invalid:\n- wrong:\n- nonprime:\n- smallpub:\n- test-vectors:").hasArg().argName("test_suite").optionalArg(true).build());
        actions.addOption(Option.builder("dh").longOpt("ecdh").desc("Do ECDH, [count] times.").hasArg().argName("count").optionalArg(true).build());
        actions.addOption(Option.builder("dhc").longOpt("ecdhc").desc("Do ECDHC, [count] times.").hasArg().argName("count").optionalArg(true).build());
        actions.addOption(Option.builder("dsa").longOpt("ecdsa").desc("Sign data with ECDSA, [count] times.").hasArg().argName("count").optionalArg(true).build());
        opts.addOptionGroup(actions);

        OptionGroup size = new OptionGroup();
        size.addOption(Option.builder("b").longOpt("bit-size").desc("Set curve size.").hasArg().argName("bits").build());
        size.addOption(Option.builder("a").longOpt("all").desc("Test all curve sizes.").build());
        opts.addOptionGroup(size);

        opts.addOption(Option.builder("fp").longOpt("prime-field").desc("Use a prime field.").build());
        opts.addOption(Option.builder("f2m").longOpt("binary-field").desc("Use a binary field.").build());

        OptionGroup curve = new OptionGroup();
        curve.addOption(Option.builder("nc").longOpt("named-curve").desc("Use a named curve, from CurveDB: <cat/id>").hasArg().argName("cat/id").build());
        curve.addOption(Option.builder("c").longOpt("curve").desc("Use curve from file <curve_file> (field,a,b,gx,gy,r,k).").hasArg().argName("curve_file").build());
        curve.addOption(Option.builder("u").longOpt("custom").desc("Use a custom curve (applet-side embedded, SECG curves).").build());
        opts.addOptionGroup(curve);

        OptionGroup pub = new OptionGroup();
        pub.addOption(Option.builder("npub").longOpt("named-public").desc("Use public key from KeyDB: <cat/id>").hasArg().argName("cat/id").build());
        pub.addOption(Option.builder("pub").longOpt("public").desc("Use public key from file <pubkey_file> (wx,wy).").hasArg().argName("pubkey_file").build());
        opts.addOptionGroup(pub);

        OptionGroup priv = new OptionGroup();
        priv.addOption(Option.builder("npriv").longOpt("named-private").desc("Use private key from KeyDB: <cat/id>").hasArg().argName("cat/id").build());
        priv.addOption(Option.builder("priv").longOpt("private").desc("Use private key from file <privkey_file> (s).").hasArg().argName("privkey_file").build());
        opts.addOptionGroup(priv);

        OptionGroup key = new OptionGroup();
        key.addOption(Option.builder("nk").longOpt("named-key").desc("Use keyPair from KeyDB: <cat/id>").hasArg().argName("cat/id").build());
        key.addOption(Option.builder("k").longOpt("key").desc("Use keyPair from file <key_file> (wx,wy,s).").hasArg().argName("key_file").build());
        opts.addOptionGroup(key);

        opts.addOption(Option.builder("i").longOpt("input").desc("Input from file <input_file>, for ECDSA signing.").hasArg().argName("input_file").build());
        opts.addOption(Option.builder("o").longOpt("output").desc("Output into file <output_file>.").hasArg().argName("output_file").build());
        opts.addOption(Option.builder("l").longOpt("log").desc("Log output into file [log_file].").hasArg().argName("log_file").optionalArg(true).build());
        opts.addOption(Option.builder("v").longOpt("verbose").desc("Turn on verbose logging.").build());

        opts.addOption(Option.builder("f").longOpt("fresh").desc("Generate fresh keys (set domain parameters before every generation).").build());
        opts.addOption(Option.builder("s").longOpt("simulate").desc("Simulate a card with jcardsim instead of using a terminal.").build());

        CommandLineParser parser = new DefaultParser();
        return parser.parse(opts, args);
    }

    /**
     * Reads and validates options, also sets defaults.
     *
     * @param cli cli object, with parsed args
     * @return whether the options are valid.
     */
    private boolean readOptions(CommandLine cli) {
        optBits = Integer.parseInt(cli.getOptionValue("bit-size", "0"));
        optAll = cli.hasOption("all");
        optPrimeField = cli.hasOption("fp");
        optBinaryField = cli.hasOption("f2m");

        optNamedCurve = cli.getOptionValue("named-curve");
        optCustomCurve = cli.hasOption("custom");
        optCurveFile = cli.getOptionValue("curve");

        optNamedPublic = cli.getOptionValue("named-public");
        optPublic = cli.getOptionValue("public");
        optAnyPublic = (optPublic != null) || (optNamedPublic != null);

        optNamedPrivate = cli.getOptionValue("named-private");
        optPrivate = cli.getOptionValue("private");
        optAnyPrivate = (optPrivate != null) || (optNamedPrivate != null);

        optNamedKey = cli.getOptionValue("named-key");
        optKey = cli.getOptionValue("key");
        optAnyKey = (optKey != null) || (optNamedKey != null);
        optAnyKeypart = optAnyKey || optAnyPublic || optAnyPrivate;

        if (cli.hasOption("log")) {
            optLog = cli.getOptionValue("log", String.format("ECTESTER_log_%d.log", System.currentTimeMillis() / 1000));
        }

        optVerbose = cli.hasOption("verbose");
        optInput = cli.getOptionValue("input");
        optOutput = cli.getOptionValue("output");
        optFresh = cli.hasOption("fresh");
        optSimulate = cli.hasOption("simulate");

        if (cli.hasOption("list-named")) {
            optListNamed = cli.getOptionValue("list-named");
            return true;
        }

        if ((optKey != null || optNamedKey != null) && (optPublic != null || optPrivate != null || optNamedPublic != null || optNamedPrivate != null)) {
            System.err.print("Can only specify the whole key with --key/--named-key or pubkey and privkey with --public/--named-public and --private/--named-private.");
            return false;
        }
        if (optBits < 0) {
            System.err.println("Bit-size must not be negative.");
            return false;
        }
        if (optBits == 0 && !optAll) {
            System.err.println("You must specify either bit-size with -b or all bit-sizes with -a.");
            return false;
        }

        if (optKey != null && optNamedKey != null || optPublic != null && optNamedPublic != null || optPrivate != null && optNamedPrivate != null) {
            System.err.println("You cannot specify both a named key and a key file.");
            return false;
        }

        if (cli.hasOption("export")) {
            if (optPrimeField == optBinaryField) {
                System.err.print("Need to specify field with -fp or -f2m. (not both)");
                return false;
            }
            if (optAnyKeypart) {
                System.err.println("Keys should not be specified when exporting curve params.");
                return false;
            }
            if (optNamedCurve != null || optCustomCurve || optCurveFile != null) {
                System.err.println("Specifying a curve for curve export makes no sense.");
                return false;
            }
            if (optOutput == null) {
                System.err.println("You have to specify an output file for curve parameter export.");
                return false;
            }
            if (optAll) {
                System.err.println("You have to specify curve bit-size with -b");
                return false;
            }

        } else if (cli.hasOption("generate")) {
            if (optPrimeField == optBinaryField) {
                System.err.print("Need to specify field with -fp or -f2m. (not both)");
                return false;
            }
            if (optAnyKeypart) {
                System.err.println("Keys should not be specified when generating keys.");
                return false;
            }
            if (optOutput == null) {
                System.err.println("You have to specify an output file for the key generation process.");
                return false;
            }
            if (optAll) {
                System.err.println("You have to specify curve bit-size with -b");
                return false;
            }

            optGenerateAmount = Integer.parseInt(cli.getOptionValue("generate", "0"));
            if (optGenerateAmount < 0) {
                System.err.println("Amount of keys generated cant be negative.");
                return false;
            }
        } else if (cli.hasOption("test")) {
            if (!optBinaryField && !optPrimeField) {
                optBinaryField = true;
                optPrimeField = true;
            }

            optTestSuite = cli.getOptionValue("test", "default").toLowerCase();
            String[] tests = new String[]{"default", "nonprime", "invalid", "test-vectors", "wrong"};
            List<String> testsList = Arrays.asList(tests);
            if (!testsList.contains(optTestSuite)) {
                System.err.println("Unknown test case. Should be one of: " + Arrays.toString(tests));
                return false;
            }

        } else if (cli.hasOption("ecdh") || cli.hasOption("ecdhc")) {
            if (optPrimeField == optBinaryField) {
                System.err.print("Need to specify field with -fp or -f2m. (not both)");
                return false;
            }
            if (optAll) {
                System.err.println("You have to specify curve bit-size with -b");
                return false;
            }

            if (cli.hasOption("ecdh")) {
                optECDHCount = Integer.parseInt(cli.getOptionValue("ecdh", "1"));
                optECDHKA = EC_Consts.KA_ECDH;
            } else if (cli.hasOption("ecdhc")) {
                optECDHCount = Integer.parseInt(cli.getOptionValue("ecdhc", "1"));
                optECDHKA = EC_Consts.KA_ECDHC;
            }
            if (optECDHCount <= 0) {
                System.err.println("ECDH count cannot be <= 0.");
                return false;
            }

        } else if (cli.hasOption("ecdsa")) {
            if (optPrimeField == optBinaryField) {
                System.err.print("Need to specify field with -fp or -f2m. (but not both)");
                return false;
            }
            if (optAll) {
                System.err.println("You have to specify curve bit-size with -b");
                return false;
            }

            if ((optAnyPublic) != (optAnyPrivate) && !optAnyKey) {
                System.err.println("You cannot only specify a part of a keypair.");
                return false;
            }

            optECDSACount = Integer.parseInt(cli.getOptionValue("ecdsa", "1"));
            if (optECDSACount <= 0) {
                System.err.println("ECDSA count cannot be <= 0.");
                return false;
            }
        }

        return true;
    }

    /**
     * List categories and named curves.
     */
    private void list() {
        Map<String, EC_Category> categories = dataStore.getCategories();
        if (optListNamed == null) {
            // print all categories, briefly
            for (EC_Category cat : categories.values()) {
                System.out.println(cat);
            }
        } else if (categories.containsKey(optListNamed)) {
            // print given category
            System.out.println(categories.get(optListNamed));
        } else {
            // print given object
            EC_Data object = dataStore.getObject(EC_Data.class, optListNamed);
            if (object != null) {
                System.out.println(object);
            } else {
                System.err.println("Named object " + optListNamed + " not found!");
            }
        }
    }

    /**
     * Prints help.
     */
    private void help() {
        HelpFormatter help = new HelpFormatter();
        help.setOptionComparator(null);
        help.printHelp("ECTester.jar", CLI_HEADER, opts, CLI_FOOTER, true);
    }

    /**
     * Exports default card/simulation EC domain parameters to output file.
     *
     * @throws CardException if APDU transmission fails
     * @throws IOException   if an IO error occurs when writing to key file.
     */
    private void export() throws CardException, IOException {
        byte keyClass = optPrimeField ? KeyPair.ALG_EC_FP : KeyPair.ALG_EC_F2M;

        List<Response> sent = new LinkedList<>();
        sent.add(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_LOCAL, (short) optBits, keyClass).send());
        sent.add(new Command.Clear(cardManager, ECTesterApplet.KEYPAIR_LOCAL).send());
        sent.add(new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_LOCAL).send());

        // Cofactor generally isn't set on the default curve parameters on cards,
        // since its not necessary for ECDH, only ECDHC which not many cards implement
        // TODO: check if its assumend to be == 1?
        short domainAll = optPrimeField ? EC_Consts.PARAMETERS_DOMAIN_FP : EC_Consts.PARAMETERS_DOMAIN_F2M;
        short domain = (short) (domainAll ^ EC_Consts.PARAMETER_K);
        Response.Export export = new Command.Export(cardManager, ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.KEY_PUBLIC, domainAll).send();
        if (!export.successful()) {
            export = new Command.Export(cardManager, ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.KEY_PUBLIC, domain).send();
        }
        sent.add(export);

        systemOutLogger.println(Response.toString(sent));

        EC_Params exported = new EC_Params(domain, export.getParams());

        FileOutputStream out = new FileOutputStream(optOutput);
        exported.writeCSV(out);
        out.close();
    }

    /**
     * Generates EC keyPairs and outputs them to output file.
     *
     * @throws CardException if APDU transmission fails
     * @throws IOException   if an IO error occurs when writing to key file.
     */
    private void generate() throws CardException, IOException {
        byte keyClass = optPrimeField ? KeyPair.ALG_EC_FP : KeyPair.ALG_EC_F2M;

        new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_LOCAL, (short) optBits, keyClass).send();
        List<Command> curve = prepareCurve(ECTesterApplet.KEYPAIR_LOCAL, (short) optBits, keyClass);

        FileWriter keysFile = new FileWriter(optOutput);
        keysFile.write("index;time;pubW;privS\n");

        int generated = 0;
        int retry = 0;
        while (generated < optGenerateAmount || optGenerateAmount == 0) {
            if (optFresh || generated == 0) {
                Command.sendAll(curve);
            }

            Command.Generate generate = new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_LOCAL);
            Response.Generate response = generate.send();
            long elapsed = response.getDuration();

            Response.Export export = new Command.Export(cardManager, ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.KEY_BOTH, EC_Consts.PARAMETERS_KEYPAIR).send();

            if (!response.successful() || !export.successful()) {
                if (retry < 10) {
                    retry++;
                    continue;
                } else {
                    System.err.println("Keys could not be generated.");
                    break;
                }
            }
            systemOutLogger.println(response.toString());

            String pub = Util.bytesToHex(export.getParameter(ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.PARAMETER_W), false);
            String priv = Util.bytesToHex(export.getParameter(ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.PARAMETER_S), false);
            String line = String.format("%d;%d;%s;%s\n", generated, elapsed / 1000000, pub, priv);
            keysFile.write(line);
            keysFile.flush();
            generated++;
        }
        keysFile.close();
    }

    /**
     * Tests Elliptic curve support for a given curve/curves.
     *
     * @throws CardException if APDU transmission fails
     * @throws IOException   if an IO error occurs when writing to key file.
     */
    private void test() throws IOException, CardException {
        List<Command> commands = new LinkedList<>();

        if (optTestSuite.equals("default")) {
            commands.add(new Command.Support(cardManager));
            if (optNamedCurve != null) {
                if (optPrimeField) {
                    commands.addAll(testCurves(optNamedCurve, KeyPair.ALG_EC_FP));
                }
                if (optBinaryField) {
                    commands.addAll(testCurves(optNamedCurve, KeyPair.ALG_EC_F2M));
                }
            } else {
                if (optAll) {
                    if (optPrimeField) {
                        //iterate over prime curve sizes used: EC_Consts.FP_SIZES
                        for (short keyLength : EC_Consts.FP_SIZES) {
                            commands.add(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_BOTH, keyLength, KeyPair.ALG_EC_FP));
                            commands.addAll(prepareCurve(ECTesterApplet.KEYPAIR_BOTH, keyLength, KeyPair.ALG_EC_FP));
                            commands.addAll(testCurve());
                            commands.add(new Command.Cleanup(cardManager));
                        }
                    }
                    if (optBinaryField) {
                        //iterate over binary curve sizes used: EC_Consts.F2M_SIZES
                        for (short keyLength : EC_Consts.F2M_SIZES) {
                            commands.add(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_BOTH, keyLength, KeyPair.ALG_EC_F2M));
                            commands.addAll(prepareCurve(ECTesterApplet.KEYPAIR_BOTH, keyLength, KeyPair.ALG_EC_F2M));
                            commands.addAll(testCurve());
                            commands.add(new Command.Cleanup(cardManager));
                        }
                    }
                } else {
                    if (optPrimeField) {
                        commands.add(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_BOTH, (short) optBits, KeyPair.ALG_EC_FP));
                        commands.addAll(prepareCurve(ECTesterApplet.KEYPAIR_BOTH, (short) optBits, KeyPair.ALG_EC_FP));
                        commands.addAll(testCurve());
                        commands.add(new Command.Cleanup(cardManager));
                    }

                    if (optBinaryField) {
                        commands.add(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_BOTH, (short) optBits, KeyPair.ALG_EC_F2M));
                        commands.addAll(prepareCurve(ECTesterApplet.KEYPAIR_BOTH, (short) optBits, KeyPair.ALG_EC_F2M));
                        commands.addAll(testCurve());
                        commands.add(new Command.Cleanup(cardManager));
                    }
                }
            }
        } else if (optTestSuite.equals("test-vectors")) {
            /* Set original curves (secg/nist/brainpool). Set keypairs from test vectors.
             * Do ECDH both ways, export and verify that the result is correct.
             *
             */
            Map<String, EC_KAResult> results = dataStore.getObjects(EC_KAResult.class, "test");
            for (EC_KAResult result : results.values()) {
                EC_Curve curve = dataStore.getObject(EC_Curve.class, result.getCurve());
                if (optNamedCurve != null && !(result.getCurve().startsWith(optNamedCurve) || result.getCurve().equals(optNamedCurve))) {
                    continue;
                }
                if (curve.getBits() != optBits && !optAll) {
                    continue;
                }
                EC_Params onekey = dataStore.getObject(EC_Keypair.class, result.getOneKey());
                if (onekey == null) {
                    onekey = dataStore.getObject(EC_Key.Private.class, result.getOneKey());
                }
                EC_Params otherkey = dataStore.getObject(EC_Keypair.class, result.getOtherKey());
                if (otherkey == null) {
                    otherkey = dataStore.getObject(EC_Key.Public.class, result.getOtherKey());
                }
                if (onekey == null || otherkey == null) {
                    throw new IOException("Test vector keys not located");
                }

                commands.add(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), curve.getField()));
                commands.add(new Command.Set(cardManager, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()));
                commands.add(new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_BOTH));
                commands.add(new Command.Set(cardManager, ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.CURVE_external, EC_Consts.PARAMETER_S, onekey.flatten(EC_Consts.PARAMETER_S)));
                commands.add(new Command.Set(cardManager, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, EC_Consts.PARAMETER_W, otherkey.flatten(EC_Consts.PARAMETER_W)));
                commands.add(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_TRUE, EC_Consts.CORRUPTION_NONE, result.getKA()));
                //TODO add compare with result.getParam(0);
                commands.add(new Command.Cleanup(cardManager));
            }

        } else {
            // These tests are dangerous, prompt before them.
            System.out.println("The test you selected (" + optTestSuite + ") is potentially dangerous.");
            System.out.println("Some of these tests have caused temporary DoS of some cards.");
            System.out.print("Do you want to proceed? (y/n): ");
            Scanner in = new Scanner(System.in);
            String confirmation = in.nextLine();
            if (!Arrays.asList("yes", "y", "Y").contains(confirmation)) {
                return;
            }
            in.close();

            if (optTestSuite.equals("wrong")) {
            /* Just do the default tests on the wrong curves.
             * These should generally fail, the curves aren't safe.
             */
                if (optPrimeField) {
                    commands.addAll(testCurves(optTestSuite, KeyPair.ALG_EC_FP));
                }
                if (optBinaryField) {
                    commands.addAll(testCurves(optTestSuite, KeyPair.ALG_EC_F2M));
                }
            } else if (optTestSuite.equals("nonprime")) {
            /* Do the default tests with the public keys set to provided nonprime keys.
             * These should fail, the curves aren't safe so that if the computation with
             * a small order public key succeeds the private key modulo the public key order
             * is revealed.
             */
                Map<String, EC_Key> keys = dataStore.getObjects(EC_Key.class, "nonprime");
                for (EC_Key key : keys.values()) {
                    EC_Curve curve = dataStore.getObject(EC_Curve.class, key.getCurve());
                    if ((curve.getBits() == optBits || optAll)) {
                        commands.add(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), curve.getField()));
                        commands.add(new Command.Set(cardManager, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()));
                        commands.add(new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_LOCAL));
                        commands.add(new Command.Set(cardManager, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, key.getParams(), key.flatten()));
                        commands.add(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_NONE, EC_Consts.KA_ECDH));
                        commands.add(new Command.Cleanup(cardManager));
                    }
                }
            } else if (optTestSuite.equals("invalid")) {
                /* Set original curves (secg/nist/brainpool). Generate local.
                 * Try ECDH with invalid public keys of increasing (or decreasing) order.
                 */
                Map<String, EC_Key.Public> pubkeys = dataStore.getObjects(EC_Key.Public.class, "invalid");
                for (EC_Key.Public key : pubkeys.values()) {
                    EC_Curve curve = dataStore.getObject(EC_Curve.class, key.getCurve());
                    if (optNamedCurve != null && !(key.getCurve().startsWith(optNamedCurve) || key.getCurve().equals(optNamedCurve))) {
                        continue;
                    }
                    if (curve.getBits() != optBits && !optAll) {
                        continue;
                    }
                    commands.add(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), curve.getField()));
                    commands.add(new Command.Set(cardManager, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()));
                    commands.add(new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_LOCAL));
                    commands.add(new Command.Set(cardManager, ECTesterApplet.KEYPAIR_REMOTE, EC_Consts.CURVE_external, key.getParams(), key.flatten()));
                    commands.add(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_NONE, EC_Consts.KA_BOTH));
                    //commands.add(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_NONE, EC_Consts.KA_ECDHC));
                    commands.add(new Command.Cleanup(cardManager));

                }
            }
        }


        List<Response> test = Command.sendAll(commands);
        systemOutLogger.println(Response.toString(test, optTestSuite));

    }

    /**
     * Performs ECDH key exchange.
     *
     * @throws CardException if APDU transmission fails
     * @throws IOException   if an IO error occurs when writing to key file.
     */
    private void ecdh() throws IOException, CardException {
        byte keyClass = optPrimeField ? KeyPair.ALG_EC_FP : KeyPair.ALG_EC_F2M;
        List<Response> prepare = new LinkedList<>();
        prepare.add(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_BOTH, (short) optBits, keyClass).send());
        prepare.addAll(Command.sendAll(prepareCurve(ECTesterApplet.KEYPAIR_BOTH, (short) optBits, keyClass)));

        systemOutLogger.println(Response.toString(prepare));

        byte pubkey = (optAnyPublic || optAnyKey) ? ECTesterApplet.KEYPAIR_REMOTE : ECTesterApplet.KEYPAIR_LOCAL;
        byte privkey = (optAnyPrivate || optAnyKey) ? ECTesterApplet.KEYPAIR_REMOTE : ECTesterApplet.KEYPAIR_LOCAL;

        List<Command> generate = new LinkedList<>();
        generate.add(new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_BOTH));
        if (optAnyPublic || optAnyPrivate || optAnyKey) {
            generate.add(prepareKey(ECTesterApplet.KEYPAIR_REMOTE));
        }

        FileWriter out = null;
        if (optOutput != null) {
            out = new FileWriter(optOutput);
            out.write("index;time;secret\n");
        }

        int retry = 0;
        int done = 0;
        while (done < optECDHCount) {
            List<Response> ecdh = Command.sendAll(generate);

            Response.ECDH perform = new Command.ECDH(cardManager, pubkey, privkey, ECTesterApplet.EXPORT_TRUE, EC_Consts.CORRUPTION_NONE, optECDHKA).send();
            ecdh.add(perform);
            systemOutLogger.println(Response.toString(ecdh));

            if (!perform.successful() || !perform.hasSecret()) {
                if (retry < 10) {
                    ++retry;
                    continue;
                } else {
                    System.err.println("Couldn't obtain ECDH secret from card response.");
                    break;
                }
            }

            if (out != null) {
                out.write(String.format("%d;%d;%s\n", done, perform.getDuration() / 1000000, Util.bytesToHex(perform.getSecret(), false)));
            }

            ++done;
        }

        if (out != null)
            out.close();
    }

    /**
     * Performs ECDSA signature, on random or provided data.
     *
     * @throws CardException if APDU transmission fails
     * @throws IOException   if an IO error occurs when writing to key file.
     */
    private void ecdsa() throws CardException, IOException {
        //read file, if asked to sign
        byte[] data = null;
        if (optInput != null) {
            File in = new File(optInput);
            long len = in.length();
            if (len == 0) {
                throw new FileNotFoundException(optInput);
            }
            data = Files.readAllBytes(in.toPath());
        }

        Command generate;
        if (optAnyKeypart) {
            generate = prepareKey(ECTesterApplet.KEYPAIR_LOCAL);
        } else {
            generate = new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_LOCAL);
        }

        byte keyClass = optPrimeField ? KeyPair.ALG_EC_FP : KeyPair.ALG_EC_F2M;
        List<Response> prepare = new LinkedList<>();
        prepare.add(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_LOCAL, (short) optBits, keyClass).send());
        prepare.addAll(Command.sendAll(prepareCurve(ECTesterApplet.KEYPAIR_LOCAL, (short) optBits, keyClass)));

        systemOutLogger.println(Response.toString(prepare));

        FileWriter out = null;
        if (optOutput != null) {
            out = new FileWriter(optOutput);
            out.write("index;time;signature\n");
        }

        int retry = 0;
        int done = 0;
        while (done < optECDSACount) {
            List<Response> ecdsa = new LinkedList<>();
            ecdsa.add(generate.send());

            Response.ECDSA perform = new Command.ECDSA(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_TRUE, data).send();
            ecdsa.add(perform);
            systemOutLogger.println(Response.toString(ecdsa));

            if (!perform.successful() || !perform.hasSignature()) {
                if (retry < 10) {
                    ++retry;
                    continue;
                } else {
                    System.err.println("Couldn't obtain ECDSA signature from card response.");
                    break;
                }
            }

            if (out != null) {
                out.write(String.format("%d;%d;%s\n", done, perform.getDuration() / 1000000, Util.bytesToHex(perform.getSignature(), false)));
            }

            ++done;
        }
        if (out != null)
            out.close();
    }

    /**
     * @param keyPair   which keyPair/s (local/remote) to set curve domain parameters on
     * @param keyLength key length to choose
     * @param keyClass  key class to choose
     * @return a list of Commands to send in order to prepare the curve on the keypairs.
     * @throws IOException if curve file cannot be found/opened
     */
    private List<Command> prepareCurve(byte keyPair, short keyLength, byte keyClass) throws IOException {
        List<Command> commands = new ArrayList<>();

        if (optCustomCurve) {
            // Set custom curve (one of the SECG curves embedded applet-side)
            short domainParams = keyClass == KeyPair.ALG_EC_FP ? EC_Consts.PARAMETERS_DOMAIN_FP : EC_Consts.PARAMETERS_DOMAIN_F2M;
            commands.add(new Command.Set(cardManager, keyPair, EC_Consts.getCurve(keyLength, keyClass), domainParams, null));
        } else if (optNamedCurve != null) {
            // Set a named curve.
            // parse optNamedCurve -> cat / id | cat | id
            EC_Curve curve = dataStore.getObject(EC_Curve.class, optNamedCurve);
            if (curve == null) {
                throw new IOException("Curve could no be found.");
            }
            if (curve.getBits() != keyLength) {
                throw new IOException("Curve bits mismatch: " + curve.getBits() + " vs " + keyLength + " entered.");
            }

            byte[] external = curve.flatten();
            if (external == null) {
                throw new IOException("Couldn't read named curve data.");
            }
            commands.add(new Command.Set(cardManager, keyPair, EC_Consts.CURVE_external, curve.getParams(), external));
        } else if (optCurveFile != null) {
            // Set curve loaded from a file
            EC_Curve curve = new EC_Curve(keyLength, keyClass);

            FileInputStream in = new FileInputStream(optCurveFile);
            curve.readCSV(in);
            in.close();

            byte[] external = curve.flatten();
            if (external == null) {
                throw new IOException("Couldn't read the curve file correctly.");
            }
            commands.add(new Command.Set(cardManager, keyPair, EC_Consts.CURVE_external, curve.getParams(), external));
        } else {
            // Set default curve
            /* This command was generally causing problems for simulating on jcardsim.
             * Since there, .clearKey() resets all the keys values, even the domain.
             * This might break some other stuff.. But should not.
             */
            //commands.add(new Command.Clear(cardManager, keyPair));
        }

        return commands;
    }

    /**
     * @param keyPair which keyPair/s to set the key params on
     * @return a CommandAPDU setting params loaded on the keyPair/s
     * @throws IOException if any of the key files cannot be found/opened
     */
    private Command prepareKey(byte keyPair) throws IOException {
        short params = EC_Consts.PARAMETERS_NONE;
        byte[] data = null;

        if (optKey != null || optNamedKey != null) {
            params |= EC_Consts.PARAMETERS_KEYPAIR;
            EC_Params keypair;
            if (optKey != null) {
                keypair = new EC_Params(EC_Consts.PARAMETERS_KEYPAIR);

                FileInputStream in = new FileInputStream(optKey);
                keypair.readCSV(in);
                in.close();
            } else {
                keypair = dataStore.getObject(EC_Keypair.class, optNamedKey);
            }

            data = keypair.flatten();
            if (data == null) {
                throw new IOException("Couldn't read the key file correctly.");
            }
        }

        if (optPublic != null || optNamedPublic != null) {
            params |= EC_Consts.PARAMETER_W;
            EC_Params pub;
            if (optPublic != null) {
                pub = new EC_Params(EC_Consts.PARAMETER_W);

                FileInputStream in = new FileInputStream(optPublic);
                pub.readCSV(in);
                in.close();
            } else {
                pub = dataStore.getObject(EC_Key.Public.class, optNamedPublic);
                if (pub == null) {
                    pub = dataStore.getObject(EC_Keypair.class, optNamedPublic);
                }
            }

            byte[] pubkey = pub.flatten(EC_Consts.PARAMETER_W);
            if (pubkey == null) {
                throw new IOException("Couldn't read the public key file correctly.");
            }
            data = pubkey;
        }
        if (optPrivate != null || optNamedPrivate != null) {
            params |= EC_Consts.PARAMETER_S;
            EC_Params priv;
            if (optPrivate != null) {
                priv = new EC_Params(EC_Consts.PARAMETER_S);

                FileInputStream in = new FileInputStream(optPrivate);
                priv.readCSV(in);
                in.close();
            } else {
                priv = dataStore.getObject(EC_Key.Public.class, optNamedPrivate);
                if (priv == null) {
                    priv = dataStore.getObject(EC_Keypair.class, optNamedPrivate);
                }
            }

            byte[] privkey = priv.flatten(EC_Consts.PARAMETER_S);
            if (privkey == null) {
                throw new IOException("Couldn't read the private key file correctly.");
            }
            data = Util.concatenate(data, privkey);
        }
        return new Command.Set(cardManager, keyPair, EC_Consts.CURVE_external, params, data);
    }

    /**
     * @return
     * @throws IOException if an IO error occurs when writing to key file.
     */
    private List<Command> testCurve() throws IOException {
        List<Command> commands = new LinkedList<>();
        commands.add(new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_BOTH));
        commands.add(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_NONE, EC_Consts.KA_ECDH));
        commands.add(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_ONE, EC_Consts.KA_ECDH));
        commands.add(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_ZERO, EC_Consts.KA_ECDH));
        commands.add(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_MAX, EC_Consts.KA_ECDH));
        commands.add(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, EC_Consts.CORRUPTION_FULLRANDOM, EC_Consts.KA_ECDH));
        commands.add(new Command.ECDSA(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, null));
        return commands;
    }

    /**
     * @param category
     * @param field
     * @return
     * @throws IOException if an IO error occurs when writing to key file.
     */
    private List<Command> testCurves(String category, byte field) throws IOException {
        List<Command> commands = new LinkedList<>();
        Map<String, EC_Curve> curves = dataStore.getObjects(EC_Curve.class, category);
        if (curves == null)
            return commands;
        for (Map.Entry<String, EC_Curve> entry : curves.entrySet()) {
            EC_Curve curve = entry.getValue();
            if (curve.getField() == field && (curve.getBits() == optBits || optAll)) {
                commands.add(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_BOTH, curve.getBits(), field));
                commands.add(new Command.Set(cardManager, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.CURVE_external, curve.getParams(), curve.flatten()));
                commands.addAll(testCurve());
                commands.add(new Command.Cleanup(cardManager));
            }
        }

        return commands;
    }

    public static void main(String[] args) {
        ECTester app = new ECTester();
        app.run(args);
    }
}
