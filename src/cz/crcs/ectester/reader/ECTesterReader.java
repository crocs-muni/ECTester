/*
 * ECTester, tool for testing Elliptic curve cryptography implementations.
 * Copyright (c) 2016-2018 Petr Svenda <petr@svenda.com>
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
import cz.crcs.ectester.common.cli.CLITools;
import cz.crcs.ectester.common.cli.Colors;
import cz.crcs.ectester.common.output.OutputLogger;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.util.ByteUtil;
import cz.crcs.ectester.common.util.CardUtil;
import cz.crcs.ectester.common.util.FileUtil;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.command.Command;
import cz.crcs.ectester.reader.output.FileTestWriter;
import cz.crcs.ectester.reader.output.ResponseWriter;
import cz.crcs.ectester.reader.response.Response;
import cz.crcs.ectester.reader.test.*;
import javacard.framework.ISO7816;
import javacard.security.KeyPair;
import org.apache.commons.cli.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.security.Security;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Scanner;
import java.util.jar.Manifest;

import static cz.crcs.ectester.applet.EC_Consts.KeyAgreement_ALG_EC_SVDP_DH;
import static cz.crcs.ectester.applet.EC_Consts.Signature_ALG_ECDSA_SHA;

/**
 * Reader part of ECTester, a tool for testing Elliptic curve support on javacards.
 *
 * @author Petr Svenda petr@svenda.com
 * @author Jan Jancar johny@neuromancer.sk
 * @version v0.3.1
 */
public class ECTesterReader {
    private CardMngr cardManager;
    private OutputLogger logger;
    private ResponseWriter respWriter;
    private Config cfg;

    private Options opts = new Options();
    public static final String VERSION = "v0.3.1";
    public static String GIT_COMMIT = "";
    private static String DESCRIPTION;
    private static String LICENSE = "MIT Licensed\nCopyright (c) 2016-2018 Petr Svenda <petr@svenda.com>";
    private static String CLI_HEADER;
    private static String CLI_FOOTER = "\n" + LICENSE;

    private static final byte[] SELECT_ECTESTERAPPLET = {(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0a,
            (byte) 0x45, (byte) 0x43, (byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x65, (byte) 0x72, (byte) 0x30, (byte) 0x31};
    private static final byte[] AID = {(byte) 0x45, (byte) 0x43, (byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x65, (byte) 0x72, (byte) 0x30, (byte) 0x31};
    private static final byte[] INSTALL_DATA = new byte[10];

    static {
        URLClassLoader cl = (URLClassLoader) ECTesterReader.class.getClassLoader();
        try {
            URL url = cl.findResource("META-INF/MANIFEST.MF");
            Manifest manifest = new Manifest(url.openStream());
            String commit = manifest.getMainAttributes().getValue("Git-Commit");
            GIT_COMMIT = (commit == null) ? "" : "(git " + commit + ")";
        } catch (Exception ignored) {
        }

        DESCRIPTION = "ECTesterReader " + VERSION + GIT_COMMIT + ", a javacard Elliptic Curve Cryptography support tester/utility.";
        CLI_HEADER = "\n" + DESCRIPTION + "\n\n";
    }

    private void run(String[] args) {
        try {
            CommandLine cli = parseArgs(args);

            cfg = new Config();
            boolean optsOk = cfg.readOptions(cli);

            //if help, print and quit
            if (cli.hasOption("help")) {
                CLITools.help("ECTesterReader.jar", CLI_HEADER, opts, CLI_FOOTER, true);
                return;
            } else if (cli.hasOption("version")) {
                CLITools.version(DESCRIPTION, LICENSE);
                return;
            }

            //if opts failed, quit
            if (!optsOk) {
                return;
            }

            //if list, print and quit
            if (cli.hasOption("list-named")) {
                CLITools.listNamed(EC_Store.getInstance(), cli.getOptionValue("list-named"));
                return;
            }

            if (cli.hasOption("list-suites")) {
                listSuites();
                return;
            }

            //init CardManager
            cardManager = new CardMngr(cfg.verbose, cfg.simulate);

            //connect or simulate connection
            if (cfg.simulate) {
                if (!cardManager.prepareLocalSimulatorApplet(AID, INSTALL_DATA, ECTesterApplet.class)) {
                    System.err.println(Colors.error("Failed to establish a simulator."));
                    System.exit(1);
                }
            } else {
                if (!cardManager.connectToCardSelect()) {
                    System.err.println(Colors.error("Failed to connect to card."));
                    System.exit(1);
                }
                ResponseAPDU selectResp = cardManager.send(SELECT_ECTESTERAPPLET);
                if ((short) selectResp.getSW() != ISO7816.SW_NO_ERROR) {
                    System.err.println(Colors.error("Failed to select ECTester applet, is it installed?"));
                    cardManager.disconnectFromCard();
                    System.exit(1);
                }
            }

            // Setup logger and respWriter
            logger = new OutputLogger(true, cfg.log);
            respWriter = new ResponseWriter(logger.getPrintStream());

            // Try adding the BouncyCastleProvider, which might be used in some parts of ECTester.
            try {
                Security.addProvider(new BouncyCastleProvider());
            } catch (SecurityException | NoClassDefFoundError ignored) {
            }

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
            } else if (cli.hasOption("info")) {
                info();
            }

            //disconnect
            cardManager.disconnectFromCard();
            logger.close();

        } catch (MissingOptionException moex) {
            System.err.println(Colors.error("Missing required options, one of:"));
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
            System.err.println(Colors.error("Option, " + maex.getOption().getOpt() + " requires an argument: " + maex.getOption().getArgName()));
        } catch (NumberFormatException nfex) {
            System.err.println(Colors.error("Not a number. " + nfex.getMessage()));
        } catch (FileNotFoundException fnfe) {
            System.err.println(Colors.error("File " + fnfe.getMessage() + " not found."));
        } catch (ParseException | IOException ex) {
            System.err.println(Colors.error(ex.getMessage()));
        } catch (CardException ex) {
            if (logger != null)
                logger.println(ex.getMessage());
            ex.printStackTrace();
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        } finally {
            if (logger != null)
                logger.flush();
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
         * -V / --version
         * -h / --help
         * -e / --export
         * -g / --generate [amount]
         * -t / --test [test_suite]
         * -dh / --ecdh [count]]
         * -dsa / --ecdsa [count]
         * -ln / --list-named [obj]
         * -ls / --list-suites
         * -nfo / --info
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
         *      --format <format>
         * -l / --log [log_file]
         *
         * -f / --fresh
         * --cleanup
         * -s / --simulate
         * -y / --yes
         * -ka/ --ka-type <type>
         * -sig/--sig-type <type>
         * -C / --color
         */
        OptionGroup actions = new OptionGroup();
        actions.setRequired(true);
        actions.addOption(Option.builder("V").longOpt("version").desc("Print version info.").build());
        actions.addOption(Option.builder("h").longOpt("help").desc("Print help.").build());
        actions.addOption(Option.builder("ln").longOpt("list-named").desc("Print the list of supported named curves and keys.").hasArg().argName("what").optionalArg(true).build());
        actions.addOption(Option.builder("ls").longOpt("list-suites").desc("List supported test suites.").build());
        actions.addOption(Option.builder("e").longOpt("export").desc("Export the defaut curve parameters of the card(if any).").build());
        actions.addOption(Option.builder("g").longOpt("generate").desc("Generate <amount> of EC keys.").hasArg().argName("amount").optionalArg(true).build());
        actions.addOption(Option.builder("t").longOpt("test").desc("Test ECC support. Optionally specify a test number to run only a part of a test suite. <test_suite>:\n- default:\n- compression:\n- invalid:\n- twist:\n- degenerate:\n- cofactor:\n- wrong:\n- signature:\n- composite:\n- test-vectors:\n- edge-cases:\n- miscellaneous:").hasArg().argName("test_suite[:from[:to]]").optionalArg(true).build());
        actions.addOption(Option.builder("dh").longOpt("ecdh").desc("Do EC KeyAgreement (ECDH...), [count] times.").hasArg().argName("count").optionalArg(true).build());
        actions.addOption(Option.builder("dsa").longOpt("ecdsa").desc("Sign data with ECDSA, [count] times.").hasArg().argName("count").optionalArg(true).build());
        actions.addOption(Option.builder("nf").longOpt("info").desc("Get applet info.").build());

        opts.addOptionGroup(actions);

        opts.addOption(Option.builder("b").longOpt("bit-size").desc("Set curve size.").hasArg().argName("bits").build());
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
        opts.addOption(Option.builder("o").longOpt("output").desc("Output into file <output_file>. The file can be prefixed by the format (one of text,yml,xml), such as: xml:<output_file>.").hasArgs().argName("output_file").build());
        opts.addOption(Option.builder("l").longOpt("log").desc("Log output into file [log_file].").hasArg().argName("log_file").optionalArg(true).build());
        opts.addOption(Option.builder("v").longOpt("verbose").desc("Turn on verbose logging.").build());
        opts.addOption(Option.builder().longOpt("format").desc("Output format to use. One of: text,yml,xml.").hasArg().argName("format").build());

        opts.addOption(Option.builder("f").longOpt("fresh").desc("Generate fresh keys (set domain parameters before every generation).").build());
        opts.addOption(Option.builder().longOpt("cleanup").desc("Send the cleanup command trigerring JCSystem.requestObjectDeletion() after some operations.").build());
        opts.addOption(Option.builder("s").longOpt("simulate").desc("Simulate a card with jcardsim instead of using a terminal.").build());
        opts.addOption(Option.builder("y").longOpt("yes").desc("Accept all warnings and prompts.").build());

        opts.addOption(Option.builder("ka").longOpt("ka-type").desc("Set KeyAgreement object [type], corresponds to JC.KeyAgreement constants.").hasArg().argName("type").optionalArg(true).build());
        opts.addOption(Option.builder("sig").longOpt("sig-type").desc("Set Signature object [type], corresponds to JC.Signature constants.").hasArg().argName("type").optionalArg(true).build());
        opts.addOption(Option.builder("C").longOpt("color").desc("Print stuff with color, requires ANSI terminal.").build());

        CommandLineParser parser = new DefaultParser();
        return parser.parse(opts, args);
    }

    private void listSuites() {
        CardTestSuite[] suites = new CardTestSuite[]{
                new CardDefaultSuite(null, null, null),
                new CardTestVectorSuite(null, null, null),
                new CardCompressionSuite(null, null, null),
                new CardWrongSuite(null, null, null),
                new CardDegenerateSuite(null, null, null),
                new CardCofactorSuite(null, null, null),
                new CardCompositeSuite(null, null, null),
                new CardInvalidSuite(null, null, null),
                new CardEdgeCasesSuite(null, null, null),
                new CardSignatureSuite(null, null, null),
                new CardTwistSuite(null, null, null),
                new CardMiscSuite(null, null, null)};
        for (CardTestSuite suite : suites) {
            System.out.println(" - " + Colors.bold(suite.getName()));
            for (String line : suite.getDescription()) {
                System.out.println("\t" + line);
            }
        }
    }

    private void info() throws CardException {
        Response.GetInfo info = new Command.GetInfo(cardManager).send();
        System.out.println(String.format("ECTester applet version: %s", info.getVersion()));
        System.out.println(String.format("ECTester applet APDU support: %s", (info.getBase() == ECTesterApplet.BASE_221) ? "basic" : "extended length"));
        System.out.println(String.format("JavaCard API version: %.1f", info.getJavaCardVersion()));
        System.out.println(String.format("JavaCard supports system cleanup: %s", info.getCleanupSupport()));
        System.out.println(String.format("Array sizes (apduBuf, ram, ram2, apduArr): %d %d %d %d", info.getApduBufferLength(), info.getRamArrayLength(), info.getRamArray2Length(), info.getApduArrayLength()));
    }

    /**
     * Exports default card/simulation EC domain parameters to output file.
     *
     * @throws CardException if APDU transmission fails
     * @throws IOException   if an IO error occurs when writing to key file.
     */
    private void export() throws CardException, IOException {
        byte keyClass = cfg.primeField ? KeyPair.ALG_EC_FP : KeyPair.ALG_EC_F2M;

        List<Response> sent = new LinkedList<>();
        sent.add(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_LOCAL, cfg.bits, keyClass).send());
        //sent.add(new Command.Clear(cardManager, ECTesterApplet.KEYPAIR_LOCAL).send());
        sent.add(new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_LOCAL).send());

        // Also support exporting set parameters, to verify they are set correctly.
        Command curve = Command.prepareCurve(cardManager, EC_Store.getInstance(), cfg, ECTesterApplet.KEYPAIR_LOCAL, cfg.bits, keyClass);
        if (curve != null) {
            sent.add(curve.send());
        }

        // Cofactor generally isn't set on the default curve parameters on cards,
        // since its not necessary for ECDH, only ECDHC which not many cards implement
        // TODO: check if its assumend to be == 1?
        short domain = cfg.primeField ? EC_Consts.PARAMETERS_DOMAIN_FP : EC_Consts.PARAMETERS_DOMAIN_F2M;
        Response.Export export = new Command.Export(cardManager, ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.KEY_PUBLIC, domain).send();
        if (!export.successful()) {
            domain = (short) (domain ^ EC_Consts.PARAMETER_K);
            export = new Command.Export(cardManager, ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.KEY_PUBLIC, domain).send();
        }
        sent.add(export);

        for (Response r : sent) {
            respWriter.outputResponse(r);
        }
        if (cfg.cleanup) {
            Response cleanup = new Command.Cleanup(cardManager).send();
            respWriter.outputResponse(cleanup);
        }

        PrintStream out = new PrintStream(FileUtil.openStream(cfg.outputs));
        byte[][] params = export.getParams();
        for (int i = 0; i < params.length; ++i) {
            out.print(ByteUtil.bytesToHex(params[i], false));
            if (i != params.length - 1) {
                out.print(",");
            }
        }
        out.close();
    }

    /**
     * Generates EC keyPairs and outputs them to output file.
     *
     * @throws CardException if APDU transmission fails
     * @throws IOException   if an IO error occurs when writing to key file.
     */
    private void generate() throws CardException, IOException {
        byte keyClass = cfg.primeField ? KeyPair.ALG_EC_FP : KeyPair.ALG_EC_F2M;
        Command curve = Command.prepareCurve(cardManager, EC_Store.getInstance(), cfg, ECTesterApplet.KEYPAIR_LOCAL, cfg.bits, keyClass);

        Response allocate = new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_LOCAL, cfg.bits, keyClass).send();
        respWriter.outputResponse(allocate);

        OutputStreamWriter keysFile = FileUtil.openFiles(cfg.outputs);
        keysFile.write("index;genTime;exportTime;pubW;privS\n");

        int generated = 0;
        int retry = 0;
        while (generated < cfg.generateAmount || cfg.generateAmount == 0) {
            if ((cfg.fresh || generated == 0) && curve != null) {
                Response fresh = curve.send();
                respWriter.outputResponse(fresh);
            }

            Command.Generate generate = new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_LOCAL);
            Response.Generate response = generate.send();
            respWriter.outputResponse(response);

            Response.Export export = new Command.Export(cardManager, ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.KEY_BOTH, EC_Consts.PARAMETERS_KEYPAIR).send();
            respWriter.outputResponse(export);

            if (!response.successful() || !export.successful()) {
                if (retry < 10) {
                    retry++;
                    continue;
                } else {
                    System.err.println(Colors.error("Keys could not be generated/exported."));
                    break;
                }
            }

            String pub = ByteUtil.bytesToHex(export.getParameter(ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.PARAMETER_W), false);
            String priv = ByteUtil.bytesToHex(export.getParameter(ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.PARAMETER_S), false);
            String line = String.format("%d;%d;%d;%s;%s\n", generated, response.getDuration() / 1000000, export.getDuration() / 1000000, pub, priv);
            keysFile.write(line);
            keysFile.flush();
            generated++;
        }
        if (cfg.cleanup) {
            Response cleanup = new Command.Cleanup(cardManager).send();
            respWriter.outputResponse(cleanup);
        }

        keysFile.close();
    }

    /**
     * Tests Elliptic curve support for a given curve/curves.
     *
     * @throws IOException if an IO error occurs
     */
    private void test() throws ParserConfigurationException, IOException {
        TestWriter writer = new FileTestWriter(cfg.format, true, cfg.outputs);

        CardTestSuite suite;

        switch (cfg.testSuite) {
            case "default":
                suite = new CardDefaultSuite(writer, cfg, cardManager);
                break;
            case "test-vectors":
                suite = new CardTestVectorSuite(writer, cfg, cardManager);
                break;
            case "compression":
                suite = new CardCompressionSuite(writer, cfg, cardManager);
                break;
            case "misc":
            case "miscellaneous":
                suite = new CardMiscSuite(writer, cfg, cardManager);
                break;
            case "signature":
                suite = new CardSignatureSuite(writer, cfg, cardManager);
                break;
            default:
                // These run are dangerous, prompt before them.
                System.out.println("The test you selected (" + cfg.testSuite + ") is potentially dangerous.");
                System.out.println("Some of these run have caused temporary(or even permanent) DoS of some cards.");
                if (!cfg.yes) {
                    System.out.print("Do you want to proceed? (y/n): ");
                    Scanner in = new Scanner(System.in);
                    String confirmation = in.nextLine().toLowerCase();
                    if (!Arrays.asList("yes", "y").contains(confirmation)) {
                        return;
                    }
                    in.close();
                }
                switch (cfg.testSuite) {
                    case "wrong":
                        suite = new CardWrongSuite(writer, cfg, cardManager);
                        break;
                    case "composite":
                        suite = new CardCompositeSuite(writer, cfg, cardManager);
                        break;
                    case "invalid":
                        suite = new CardInvalidSuite(writer, cfg, cardManager);
                        break;
                    case "degenerate":
                        suite = new CardDegenerateSuite(writer, cfg, cardManager);
                        break;
                    case "twist":
                        suite = new CardTwistSuite(writer, cfg, cardManager);
                        break;
                    case "cofactor":
                        suite = new CardCofactorSuite(writer, cfg, cardManager);
                        break;
                    case "edge-cases":
                        suite = new CardEdgeCasesSuite(writer, cfg, cardManager);
                        break;
                    default:
                        System.err.println(Colors.error("Unknown test suite."));
                        return;
                }
                break;
        }

        suite.run(cfg.testFrom, cfg.testTo);
    }

    /**
     * Performs ECDH key exchange.
     *
     * @throws CardException if APDU transmission fails
     * @throws IOException   if an IO error occurs when writing to key file.
     */
    private void ecdh() throws IOException, CardException {
        byte keyClass = cfg.primeField ? KeyPair.ALG_EC_FP : KeyPair.ALG_EC_F2M;
        Command curve = Command.prepareCurve(cardManager, EC_Store.getInstance(), cfg, ECTesterApplet.KEYPAIR_BOTH, cfg.bits, keyClass);
        List<Response> prepare = new LinkedList<>();
        prepare.add(new Command.AllocateKeyAgreement(cardManager, cfg.ECKAType).send()); // Prepare KeyAgreement or required type
        prepare.add(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_BOTH, cfg.bits, keyClass).send());
        if (curve != null)
            prepare.add(curve.send());

        for (Response r : prepare) {
            respWriter.outputResponse(r);
        }

        byte pubkey = (cfg.anyPublicKey || cfg.anyKey) ? ECTesterApplet.KEYPAIR_REMOTE : ECTesterApplet.KEYPAIR_LOCAL;
        byte privkey = (cfg.anyPrivateKey || cfg.anyKey) ? ECTesterApplet.KEYPAIR_REMOTE : ECTesterApplet.KEYPAIR_LOCAL;

        List<Command> generate = new LinkedList<>();
        generate.add(new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_BOTH));
        if (cfg.anyPublicKey || cfg.anyPrivateKey || cfg.anyKey) {
            generate.add(Command.prepareKey(cardManager, EC_Store.getInstance(), cfg, ECTesterApplet.KEYPAIR_REMOTE));
        }

        OutputStreamWriter out = null;
        if (cfg.outputs != null) {
            out = FileUtil.openFiles(cfg.outputs);
            out.write("index;time;pubW;privS;secret\n");
        }

        int retry = 0;
        int done = 0;
        while (done < cfg.ECKACount) {
            List<Response> ecdh = Command.sendAll(generate);
            for (Response r : ecdh) {
                respWriter.outputResponse(r);
            }

            Response.Export export = new Command.Export(cardManager, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.KEY_BOTH, EC_Consts.PARAMETERS_KEYPAIR).send();
            respWriter.outputResponse(export);
            byte pubkey_bytes[] = export.getParameter(pubkey, EC_Consts.PARAMETER_W);
            byte privkey_bytes[] = export.getParameter(privkey, EC_Consts.PARAMETER_S);

            Response.ECDH perform = new Command.ECDH(cardManager, pubkey, privkey, ECTesterApplet.EXPORT_TRUE, EC_Consts.TRANSFORMATION_NONE, cfg.ECKAType).send();
            respWriter.outputResponse(perform);

            if (!perform.successful() || !perform.hasSecret()) {
                if (retry < 10) {
                    ++retry;
                    continue;
                } else {
                    System.err.println(Colors.error("Couldn't obtain ECDH secret from card response."));
                    break;
                }
            }

            if (out != null) {
                out.write(String.format("%d;%d;%s;%s;%s\n", done, perform.getDuration() / 1000000, ByteUtil.bytesToHex(pubkey_bytes, false), ByteUtil.bytesToHex(privkey_bytes, false), ByteUtil.bytesToHex(perform.getSecret(), false)));
            }

            ++done;
        }
        if (cfg.cleanup) {
            Response cleanup = new Command.Cleanup(cardManager).send();
            respWriter.outputResponse(cleanup);
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
        if (cfg.input != null) {
            File in = new File(cfg.input);
            long len = in.length();
            if (len == 0) {
                throw new FileNotFoundException(cfg.input);
            }
            data = Files.readAllBytes(in.toPath());
        }

        Command generate;
        if (cfg.anyKeypart) {
            generate = Command.prepareKey(cardManager, EC_Store.getInstance(), cfg, ECTesterApplet.KEYPAIR_LOCAL);
        } else {
            generate = new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_LOCAL);
        }

        byte keyClass = cfg.primeField ? KeyPair.ALG_EC_FP : KeyPair.ALG_EC_F2M;
        List<Response> prepare = new LinkedList<>();
        prepare.add(new Command.AllocateSignature(cardManager, cfg.ECDSAType).send());
        prepare.add(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_LOCAL, cfg.bits, keyClass).send());
        Command curve = Command.prepareCurve(cardManager, EC_Store.getInstance(), cfg, ECTesterApplet.KEYPAIR_LOCAL, cfg.bits, keyClass);
        if (curve != null)
            prepare.add(curve.send());

        for (Response r : prepare) {
            respWriter.outputResponse(r);
        }

        OutputStreamWriter out = FileUtil.openFiles(cfg.outputs);
        if (out != null) {
            out.write("index;time;signature\n");
        }

        int retry = 0;
        int done = 0;
        while (done < cfg.ECDSACount) {
            respWriter.outputResponse(generate.send());

            Response.ECDSA perform = new Command.ECDSA(cardManager, ECTesterApplet.KEYPAIR_LOCAL, cfg.ECDSAType, ECTesterApplet.EXPORT_TRUE, data).send();
            respWriter.outputResponse(perform);

            if (!perform.successful() || !perform.hasSignature()) {
                if (retry < 10) {
                    ++retry;
                    continue;
                } else {
                    System.err.println(Colors.error("Couldn't obtain ECDSA signature from card response."));
                    break;
                }
            }

            if (out != null) {
                out.write(String.format("%d;%d;%s\n", done, perform.getDuration() / 1000000, ByteUtil.bytesToHex(perform.getSignature(), false)));
            }

            ++done;
        }
        if (cfg.cleanup) {
            Response cleanup = new Command.Cleanup(cardManager).send();
            respWriter.outputResponse(cleanup);
        }
        if (out != null)
            out.close();
    }

    public static void main(String[] args) {
        ECTesterReader app = new ECTesterReader();
        app.run(args);
    }

    public static class Config {

        //Options
        public short bits;
        public boolean all;
        public boolean primeField = false;
        public boolean binaryField = false;


        public String namedCurve;
        public String curveFile;
        public boolean customCurve = false;

        public boolean anyPublicKey = false;
        public String namedPublicKey;
        public String publicKey;

        public boolean anyPrivateKey = false;
        public String namedPrivateKey;
        public String privateKey;

        public boolean anyKey = false;
        public String namedKey;
        public String key;

        public boolean anyKeypart = false;

        public String log;

        public boolean verbose = false;
        public String input;
        public String[] outputs;
        public boolean fresh = false;
        public boolean cleanup = false;
        public boolean simulate = false;
        public boolean yes = false;
        public String format;
        public boolean color;

        //Action-related options
        public String listNamed;
        public String testSuite;
        public int testFrom;
        public int testTo;
        public int generateAmount;
        public int ECKACount;
        public byte ECKAType = KeyAgreement_ALG_EC_SVDP_DH;
        public int ECDSACount;
        public byte ECDSAType = Signature_ALG_ECDSA_SHA;

        /**
         * Reads and validates options, also sets defaults.
         *
         * @param cli cli object, with parsed args
         * @return whether the options are valid.
         */
        boolean readOptions(CommandLine cli) {
            bits = Short.parseShort(cli.getOptionValue("bit-size", "0"));
            all = cli.hasOption("all");
            primeField = cli.hasOption("fp");
            binaryField = cli.hasOption("f2m");


            namedCurve = cli.getOptionValue("named-curve");
            customCurve = cli.hasOption("custom");
            curveFile = cli.getOptionValue("curve");

            namedPublicKey = cli.getOptionValue("named-public");
            publicKey = cli.getOptionValue("public");
            anyPublicKey = (publicKey != null) || (namedPublicKey != null);

            namedPrivateKey = cli.getOptionValue("named-private");
            privateKey = cli.getOptionValue("private");
            anyPrivateKey = (privateKey != null) || (namedPrivateKey != null);

            namedKey = cli.getOptionValue("named-key");
            key = cli.getOptionValue("key");
            anyKey = (key != null) || (namedKey != null);
            anyKeypart = anyKey || anyPublicKey || anyPrivateKey;

            if (cli.hasOption("log")) {
                log = cli.getOptionValue("log", String.format("ECTESTER_log_%d.log", System.currentTimeMillis() / 1000));
            }

            verbose = cli.hasOption("verbose");
            input = cli.getOptionValue("input");
            outputs = cli.getOptionValues("output");
            fresh = cli.hasOption("fresh");
            cleanup = cli.hasOption("cleanup");
            simulate = cli.hasOption("simulate");
            yes = cli.hasOption("yes");
            color = cli.hasOption("color");
            Colors.enabled = color;

            if (cli.hasOption("list-named")) {
                listNamed = cli.getOptionValue("list-named");
                return true;
            }

            format = cli.getOptionValue("format");
            String formats[] = new String[]{"text", "xml", "yaml", "yml"};
            if (format != null && !Arrays.asList(formats).contains(format)) {
                System.err.println(Colors.error("Wrong output format " + format + ". Should be one of " + Arrays.toString(formats)));
                return false;
            }

            if ((key != null || namedKey != null) && (anyPublicKey || anyPrivateKey)) {
                System.err.print(Colors.error("Can only specify the whole key with --key/--named-key or pubkey and privkey with --public/--named-public and --private/--named-private."));
                return false;
            }
            if (bits < 0) {
                System.err.println(Colors.error("Bit-size must not be negative."));
                return false;
            }

            if (key != null && namedKey != null || publicKey != null && namedPublicKey != null || privateKey != null && namedPrivateKey != null) {
                System.err.println(Colors.error("You cannot specify both a named key and a key file."));
                return false;
            }

            if (cli.hasOption("export")) {
                if (primeField == binaryField) {
                    System.err.print(Colors.error("Need to specify field with -fp or -f2m. (not both)"));
                    return false;
                }
                if (anyKeypart) {
                    System.err.println(Colors.error("Keys should not be specified when exporting curve params."));
                    return false;
                }
                if (outputs == null) {
                    System.err.println(Colors.error("You have to specify an output file for curve parameter export."));
                    return false;
                }
                if (all || bits == 0) {
                    System.err.println(Colors.error("You have to specify curve bit-size with -b"));
                    return false;
                }
            } else if (cli.hasOption("generate")) {
                if (primeField == binaryField) {
                    System.err.print(Colors.error("Need to specify field with -fp or -f2m. (not both)"));
                    return false;
                }
                if (anyKeypart) {
                    System.err.println(Colors.error("Keys should not be specified when generating keys."));
                    return false;
                }
                if (outputs == null) {
                    System.err.println(Colors.error("You have to specify an output file for the key generation process."));
                    return false;
                }
                if (all || bits == 0) {
                    System.err.println(Colors.error("You have to specify curve bit-size with -b"));
                    return false;
                }

                generateAmount = Integer.parseInt(cli.getOptionValue("generate", "0"));
                if (generateAmount < 0) {
                    System.err.println(Colors.error("Amount of keys generated cant be negative."));
                    return false;
                }
            } else if (cli.hasOption("test")) {
                if (!(binaryField || primeField)) {
                    binaryField = true;
                    primeField = true;
                }

                String suiteOpt = cli.getOptionValue("test", "default").toLowerCase();
                if (suiteOpt.contains(":")) {
                    String[] parts = suiteOpt.split(":");
                    testSuite = parts[0];
                    try {
                        testFrom = Integer.parseInt(parts[1]);
                    } catch (NumberFormatException nfe) {
                        System.err.println("Invalid test from number: " + parts[1] + ".");
                        return false;
                    }
                    if (parts.length == 3) {
                        try {
                            testTo = Integer.parseInt(parts[2]);
                        } catch (NumberFormatException nfe) {
                            System.err.println("Invalid test to number: " + parts[2] + ".");
                            return false;
                        }
                    } else if (parts.length != 2) {
                        System.err.println("Invalid test suite selection.");
                        return false;
                    } else {
                        testTo = -1;
                    }
                } else {
                    testSuite = suiteOpt;
                    testFrom = 0;
                    testTo = -1;
                }
                String[] tests = new String[]{"default", "composite", "compression", "invalid", "degenerate", "test-vectors", "wrong", "twist", "cofactor", "edge-cases", "miscellaneous", "signature"};
                if (!Arrays.asList(tests).contains(testSuite)) {
                    System.err.println(Colors.error("Unknown test suite " + testSuite + ". Should be one of: " + Arrays.toString(tests)));
                    return false;
                }
            } else if (cli.hasOption("ecdh")) {
                if (primeField == binaryField) {
                    System.err.print(Colors.error("Need to specify field with -fp or -f2m. (not both)"));
                    return false;
                }
                if (all || bits == 0) {
                    System.err.println(Colors.error("You have to specify curve bit-size with -b"));
                    return false;
                }

                ECKACount = Integer.parseInt(cli.getOptionValue("ecdh", "1"));
                if (ECKACount <= 0) {
                    System.err.println(Colors.error("ECDH count cannot be <= 0."));
                    return false;
                }

                ECKAType = CardUtil.parseKAType(cli.getOptionValue("ka-type", "1"));
            } else if (cli.hasOption("ecdsa")) {
                if (primeField == binaryField) {
                    System.err.print(Colors.error("Need to specify field with -fp or -f2m. (but not both)"));
                    return false;
                }
                if (all || bits == 0) {
                    System.err.println(Colors.error("You have to specify curve bit-size with -b"));
                    return false;
                }

                if ((anyPublicKey) != (anyPrivateKey) && !anyKey) {
                    System.err.println(Colors.error("You cannot only specify a part of a keypair."));
                    return false;
                }

                ECDSACount = Integer.parseInt(cli.getOptionValue("ecdsa", "1"));
                if (ECDSACount <= 0) {
                    System.err.println(Colors.error("ECDSA count cannot be <= 0."));
                    return false;
                }

                ECDSAType = CardUtil.parseSigType(cli.getOptionValue("sig-type", "17"));
            }
            return true;
        }
    }
}
