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
import cz.crcs.ectester.common.ec.EC_Params;
import cz.crcs.ectester.common.output.OutputLogger;
import cz.crcs.ectester.common.output.TestWriter;
import cz.crcs.ectester.common.util.ByteUtil;
import cz.crcs.ectester.common.util.CardUtil;
import cz.crcs.ectester.common.util.FileUtil;
import cz.crcs.ectester.data.EC_Store;
import cz.crcs.ectester.reader.command.Command;
import cz.crcs.ectester.reader.output.*;
import cz.crcs.ectester.reader.response.Response;
import cz.crcs.ectester.reader.test.*;
import javacard.security.KeyPair;
import org.apache.commons.cli.*;

import javax.smartcardio.CardException;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Scanner;

import static cz.crcs.ectester.applet.ECTesterApplet.KeyAgreement_ALG_EC_SVDP_DH;
import static cz.crcs.ectester.applet.ECTesterApplet.Signature_ALG_ECDSA_SHA;

/**
 * Reader part of ECTester, a tool for testing Elliptic curve support on javacards.
 *
 * @author Petr Svenda petr@svenda.com
 * @author Jan Jancar johny@neuromancer.sk
 * @version v0.2.0
 */
public class ECTesterReader {
    private CardMngr cardManager;
    private OutputLogger logger;
    private ResponseWriter respWriter;
    private Config cfg;

    private Options opts = new Options();
    private static final String VERSION = "v0.2.0";
    private static final String DESCRIPTION = "ECTesterReader " + VERSION + ", a javacard Elliptic Curve Cryptography support tester/utility.";
    private static final String LICENSE = "MIT Licensed\nCopyright (c) 2016-2017 Petr Svenda <petr@svenda.com>";
    private static final String CLI_HEADER = "\n" + DESCRIPTION + "\n\n";
    private static final String CLI_FOOTER = "\n" + LICENSE;

    private static final byte[] SELECT_ECTESTERAPPLET = {(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0a,
            (byte) 0x45, (byte) 0x43, (byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x65, (byte) 0x72, (byte) 0x30, (byte) 0x31};
    private static final byte[] AID = {(byte) 0x45, (byte) 0x43, (byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x65, (byte) 0x72, (byte) 0x30, (byte) 0x31};
    private static final byte[] INSTALL_DATA = new byte[10];

    private void run(String[] args) {
        try {
            CommandLine cli = parseArgs(args);

            //if help, print and quit
            if (cli.hasOption("help")) {
                CLITools.help("ECTesterReader.jar", CLI_HEADER, opts, CLI_FOOTER, true);
                return;
            } else if (cli.hasOption("version")) {
                CLITools.version(DESCRIPTION, LICENSE);
                return;
            }
            cfg = new Config();

            //if not, read other options first, into attributes, then do action
            if (!cfg.readOptions(cli)) {
                return;
            }

            //if list, print and quit
            if (cli.hasOption("list-named")) {
                CLITools.listNamed(EC_Store.getInstance(), cli.getOptionValue("list-named"));
                return;
            }

            //init CardManager
            cardManager = new CardMngr(cfg.verbose, cfg.simulate);

            //connect or simulate connection
            if (cfg.simulate) {
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

            // Setup logger, testWriter and respWriter
            logger = new OutputLogger(true, cfg.log);

            respWriter = new ResponseWriter(logger.getPrintStream());

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
            logger.close();

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
        } catch (ParseException | IOException ex) {
            System.err.println(ex.getMessage());
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
         * -s / --simulate
         * -y / --yes
         * -ka/ --ka-type <type>
         * -sig/--sig-type <type>
         */
        OptionGroup actions = new OptionGroup();
        actions.setRequired(true);
        actions.addOption(Option.builder("V").longOpt("version").desc("Print version info.").build());
        actions.addOption(Option.builder("h").longOpt("help").desc("Print help.").build());
        actions.addOption(Option.builder("ln").longOpt("list-named").desc("Print the list of supported named curves and keys.").hasArg().argName("what").optionalArg(true).build());
        actions.addOption(Option.builder("e").longOpt("export").desc("Export the defaut curve parameters of the card(if any).").build());
        actions.addOption(Option.builder("g").longOpt("generate").desc("Generate [amount] of EC keys.").hasArg().argName("amount").optionalArg(true).build());
        actions.addOption(Option.builder("t").longOpt("test").desc("Test ECC support. [test_suite]:\n- default:\n- invalid:\n- twist:\n- wrong:\n- composite:\n- test-vectors:").hasArg().argName("test_suite").optionalArg(true).build());
        actions.addOption(Option.builder("dh").longOpt("ecdh").desc("Do EC KeyAgreement (ECDH...), [count] times.").hasArg().argName("count").optionalArg(true).build());
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
        opts.addOption(Option.builder("o").longOpt("output").desc("Output into file <output_file>. The file can be prefixed by the format (one of text,yml,xml), such as: xml:<output_file>.").hasArgs().argName("output_file").build());
        opts.addOption(Option.builder("l").longOpt("log").desc("Log output into file [log_file].").hasArg().argName("log_file").optionalArg(true).build());
        opts.addOption(Option.builder("v").longOpt("verbose").desc("Turn on verbose logging.").build());
        opts.addOption(Option.builder().longOpt("format").desc("Output format to use. One of: text,yml,xml.").hasArg().argName("format").build());

        opts.addOption(Option.builder("f").longOpt("fresh").desc("Generate fresh keys (set domain parameters before every generation).").build());
        opts.addOption(Option.builder("s").longOpt("simulate").desc("Simulate a card with jcardsim instead of using a terminal.").build());
        opts.addOption(Option.builder("y").longOpt("yes").desc("Accept all warnings and prompts.").build());

        opts.addOption(Option.builder("ka").longOpt("ka-type").desc("Set KeyAgreement object [type], corresponds to JC.KeyAgreement constants.").hasArg().argName("type").optionalArg(true).build());
        opts.addOption(Option.builder("sig").longOpt("sig-type").desc("Set Signature object [type], corresponds to JC.Signature constants.").hasArg().argName("type").optionalArg(true).build());

        CommandLineParser parser = new DefaultParser();
        return parser.parse(opts, args);
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
        sent.add(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_LOCAL, (short) cfg.bits, keyClass).send());
        sent.add(new Command.Clear(cardManager, ECTesterApplet.KEYPAIR_LOCAL).send());
        sent.add(new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_LOCAL).send());

        // Cofactor generally isn't set on the default curve parameters on cards,
        // since its not necessary for ECDH, only ECDHC which not many cards implement
        // TODO: check if its assumend to be == 1?
        short domainAll = cfg.primeField ? EC_Consts.PARAMETERS_DOMAIN_FP : EC_Consts.PARAMETERS_DOMAIN_F2M;
        short domain = (short) (domainAll ^ EC_Consts.PARAMETER_K);
        Response.Export export = new Command.Export(cardManager, ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.KEY_PUBLIC, domainAll).send();
        if (!export.successful()) {
            export = new Command.Export(cardManager, ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.KEY_PUBLIC, domain).send();
        }
        sent.add(export);

        for (Response r : sent) {
            respWriter.outputResponse(r);
        }

        EC_Params exported = new EC_Params(domain, export.getParams());

        OutputStream out = FileUtil.openStream(cfg.outputs);
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
        byte keyClass = cfg.primeField ? KeyPair.ALG_EC_FP : KeyPair.ALG_EC_F2M;

        Response allocate = new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_LOCAL, cfg.bits, keyClass).send();
        respWriter.outputResponse(allocate);
        Command curve = Command.prepareCurve(cardManager, EC_Store.getInstance(), cfg, ECTesterApplet.KEYPAIR_LOCAL, (short) cfg.bits, keyClass);

        OutputStreamWriter keysFile = FileUtil.openFiles(cfg.outputs);
        keysFile.write("index;time;pubW;privS\n");

        int generated = 0;
        int retry = 0;
        while (generated < cfg.generateAmount || cfg.generateAmount == 0) {
            if ((cfg.fresh || generated == 0) && curve != null) {
                Response fresh = curve.send();
                respWriter.outputResponse(fresh);
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
            respWriter.outputResponse(response);

            String pub = ByteUtil.bytesToHex(export.getParameter(ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.PARAMETER_W), false);
            String priv = ByteUtil.bytesToHex(export.getParameter(ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.PARAMETER_S), false);
            String line = String.format("%d;%d;%s;%s\n", generated, elapsed / 1000000, pub, priv);
            keysFile.write(line);
            keysFile.flush();
            generated++;
        }
        Response cleanup = new Command.Cleanup(cardManager).send();
        respWriter.outputResponse(cleanup);

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
                        suite = new CardWrongCurvesSuite(writer, cfg, cardManager);
                        break;
                    case "composite":
                        suite = new CardCompositeCurvesSuite(writer, cfg, cardManager);
                        break;
                    case "invalid":
                        suite = new CardInvalidCurvesSuite(writer, cfg, cardManager);
                        break;
                    case "twist":
                        suite = new CardTwistTestSuite(writer, cfg, cardManager);
                        break;
                    default:
                        System.err.println("Unknown test suite.");
                        return;
                }
                break;
        }

        suite.run();
    }

    /**
     * Performs ECDH key exchange.
     *
     * @throws CardException if APDU transmission fails
     * @throws IOException   if an IO error occurs when writing to key file.
     */
    private void ecdh() throws IOException, CardException {
        byte keyClass = cfg.primeField ? KeyPair.ALG_EC_FP : KeyPair.ALG_EC_F2M;
        List<Response> prepare = new LinkedList<>();
        prepare.add(new Command.AllocateKeyAgreement(cardManager, cfg.ECKAType).send()); // Prepare KeyAgreement or required type
        prepare.add(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_BOTH, (short) cfg.bits, keyClass).send());
        Command curve = Command.prepareCurve(cardManager, EC_Store.getInstance(), cfg, ECTesterApplet.KEYPAIR_BOTH, (short) cfg.bits, keyClass);
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

            Response.Export export = new Command.Export(cardManager, ECTesterApplet.KEYPAIR_BOTH, EC_Consts.KEY_BOTH, EC_Consts.PARAMETERS_KEYPAIR).send();
            ecdh.add(export);
            byte pubkey_bytes[] = export.getParameter(pubkey, EC_Consts.PARAMETER_W);
            byte privkey_bytes[] = export.getParameter(privkey, EC_Consts.PARAMETER_S);

            Response.ECDH perform = new Command.ECDH(cardManager, pubkey, privkey, ECTesterApplet.EXPORT_TRUE, EC_Consts.CORRUPTION_NONE, cfg.ECKAType).send();
            ecdh.add(perform);
            for (Response r : ecdh) {
                respWriter.outputResponse(r);
            }

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
                out.write(String.format("%d;%d;%s;%s;%s\n", done, perform.getDuration() / 1000000, ByteUtil.bytesToHex(pubkey_bytes, false), ByteUtil.bytesToHex(privkey_bytes, false), ByteUtil.bytesToHex(perform.getSecret(), false)));
            }

            ++done;
        }
        Response cleanup = new Command.Cleanup(cardManager).send();
        respWriter.outputResponse(cleanup);

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
        prepare.add(new Command.Allocate(cardManager, ECTesterApplet.KEYPAIR_LOCAL, (short) cfg.bits, keyClass).send());
        Command curve = Command.prepareCurve(cardManager, EC_Store.getInstance(), cfg, ECTesterApplet.KEYPAIR_LOCAL, (short) cfg.bits, keyClass);
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
            List<Response> ecdsa = new LinkedList<>();
            ecdsa.add(generate.send());

            Response.ECDSA perform = new Command.ECDSA(cardManager, ECTesterApplet.KEYPAIR_LOCAL, cfg.ECDSAType, ECTesterApplet.EXPORT_TRUE, data).send();
            ecdsa.add(perform);
            for (Response r : ecdsa) {
                respWriter.outputResponse(r);
            }

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
                out.write(String.format("%d;%d;%s\n", done, perform.getDuration() / 1000000, ByteUtil.bytesToHex(perform.getSignature(), false)));
            }

            ++done;
        }
        Response cleanup = new Command.Cleanup(cardManager).send();
        respWriter.outputResponse(cleanup);

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
        public boolean simulate = false;
        public boolean yes = false;
        public String format;

        //Action-related options
        public String listNamed;
        public String testSuite;
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
            simulate = cli.hasOption("simulate");
            yes = cli.hasOption("yes");

            if (cli.hasOption("list-named")) {
                listNamed = cli.getOptionValue("list-named");
                return true;
            }

            format = cli.getOptionValue("format");
            String formats[] = new String[]{"text", "xml", "yaml", "yml"};
            if (format != null && !Arrays.asList(formats).contains(format)) {
                System.err.println("Wrong output format " + format + ". Should be one of " + Arrays.toString(formats));
                return false;
            }

            if ((key != null || namedKey != null) && (anyPublicKey || anyPrivateKey)) {
                System.err.print("Can only specify the whole key with --key/--named-key or pubkey and privkey with --public/--named-public and --private/--named-private.");
                return false;
            }
            if (bits < 0) {
                System.err.println("Bit-size must not be negative.");
                return false;
            }

            if (key != null && namedKey != null || publicKey != null && namedPublicKey != null || privateKey != null && namedPrivateKey != null) {
                System.err.println("You cannot specify both a named key and a key file.");
                return false;
            }

            if (cli.hasOption("export")) {
                if (primeField == binaryField) {
                    System.err.print("Need to specify field with -fp or -f2m. (not both)");
                    return false;
                }
                if (anyKeypart) {
                    System.err.println("Keys should not be specified when exporting curve params.");
                    return false;
                }
                if (namedCurve != null || customCurve || curveFile != null) {
                    System.err.println("Specifying a curve for curve export makes no sense.");
                    return false;
                }
                if (outputs == null) {
                    System.err.println("You have to specify an output file for curve parameter export.");
                    return false;
                }
                if (all || bits == 0) {
                    System.err.println("You have to specify curve bit-size with -b");
                    return false;
                }
            } else if (cli.hasOption("generate")) {
                if (primeField == binaryField) {
                    System.err.print("Need to specify field with -fp or -f2m. (not both)");
                    return false;
                }
                if (anyKeypart) {
                    System.err.println("Keys should not be specified when generating keys.");
                    return false;
                }
                if (outputs == null) {
                    System.err.println("You have to specify an output file for the key generation process.");
                    return false;
                }
                if (all || bits == 0) {
                    System.err.println("You have to specify curve bit-size with -b");
                    return false;
                }

                generateAmount = Integer.parseInt(cli.getOptionValue("generate", "0"));
                if (generateAmount < 0) {
                    System.err.println("Amount of keys generated cant be negative.");
                    return false;
                }
            } else if (cli.hasOption("test")) {
                if (!(binaryField || primeField)) {
                    binaryField = true;
                    primeField = true;
                }

                testSuite = cli.getOptionValue("test", "default").toLowerCase();
                String[] tests = new String[]{"default", "composite", "invalid", "test-vectors", "wrong", "twist"};
                if (!Arrays.asList(tests).contains(testSuite)) {
                    System.err.println("Unknown test suite " + testSuite + ". Should be one of: " + Arrays.toString(tests));
                    return false;
                }
            } else if (cli.hasOption("ecdh")) {
                if (primeField == binaryField) {
                    System.err.print("Need to specify field with -fp or -f2m. (not both)");
                    return false;
                }
                if (all || bits == 0) {
                    System.err.println("You have to specify curve bit-size with -b");
                    return false;
                }

                ECKACount = Integer.parseInt(cli.getOptionValue("ecdh", "1"));
                if (ECKACount <= 0) {
                    System.err.println("ECDH count cannot be <= 0.");
                    return false;
                }

                ECKAType = CardUtil.parseKAType(cli.getOptionValue("ka-type", "1"));
            } else if (cli.hasOption("ecdsa")) {
                if (primeField == binaryField) {
                    System.err.print("Need to specify field with -fp or -f2m. (but not both)");
                    return false;
                }
                if (all || bits == 0) {
                    System.err.println("You have to specify curve bit-size with -b");
                    return false;
                }

                if ((anyPublicKey) != (anyPrivateKey) && !anyKey) {
                    System.err.println("You cannot only specify a part of a keypair.");
                    return false;
                }

                ECDSACount = Integer.parseInt(cli.getOptionValue("ecdsa", "1"));
                if (ECDSACount <= 0) {
                    System.err.println("ECDSA count cannot be <= 0.");
                    return false;
                }

                ECDSAType = CardUtil.parseSigType(cli.getOptionValue("sig-type", "17"));
            }
            return true;
        }
    }
}
