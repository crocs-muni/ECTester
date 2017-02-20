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
import javacard.security.KeyPair;
import org.apache.commons.cli.*;

import javax.smartcardio.CardException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * Reader part of ECTester, a tool for testing Elliptic curve support on javacards.
 *
 * @author Petr Svenda petr@svenda.com
 * @author Jan Jancar johny@neuromancer.sk
 */
public class ECTester {

    private CardMngr cardManager = null;
    private DirtyLogger systemOutLogger = null;

    //Options
    private int optBits;
    private boolean optAll;
    private boolean optPrimeField = false;
    private boolean optBinaryField = false;

    private String optNamedCurve = null;
    private String optCurveFile = null;
    private boolean optCustomCurve = false;

    private String optNamedPublic = null;
    private String optPublic = null;

    private String optNamedPrivate = null;
    private String optPrivate = null;

    private String optNamedKey = null;
    private String optKey = null;

    private String optLog = null;
    private String optOutput = null;
    private boolean optFresh = false;
    private boolean optSimulate = false;

    //Action-related options
    private int optGenerateAmount;
    private String optECDSASign;

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
            cardManager = new CardMngr(optSimulate);

            //connect or simulate connection
            if (optSimulate) {
                if (!cardManager.prepareLocalSimulatorApplet(AID, INSTALL_DATA, ECTesterApplet.class)) {
                    System.err.println("Failed to establish a simulator.");
                    return;
                }
            } else {
                if (!cardManager.connectToCardSelect()) {
                    System.err.println("Failed to connect to card.");
                    return;
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
            } else if (cli.hasOption("ecdh")) {
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
                        System.err.println(o);
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
         * -t / --test
         * -dh / --ecdh
         * -dsa / --ecdsa [data_file]
         *
         * Options:
         * -b / --bit-size [b] // -a / --all
         *
         * -fp / --prime-field
         * -f2m / --binary-field
         *
         * -u / --custom
         * -n / --named [cat/id|id|cat]
         * -c / --curve [curve_file] field,a,b,gx,gy,r,k
         *
         * -pub / --public [pubkey_file] wx,wy
         * -priv / --private [privkey_file] s
         * -k / --key [key_file] wx,wy,s
         *
         * -o / --output [output_file]
         * -s / --simulate
         */
        OptionGroup actions = new OptionGroup();
        actions.setRequired(true);
        actions.addOption(Option.builder("h").longOpt("help").desc("Print help.").build());
        actions.addOption(Option.builder("e").longOpt("export").desc("Export the defaut curve parameters of the card(if any).").build());
        actions.addOption(Option.builder("g").longOpt("generate").desc("Generate [amount] of EC keys.").hasArg().argName("amount").optionalArg(true).build());
        actions.addOption(Option.builder("t").longOpt("test").desc("Test ECC support.").build());
        actions.addOption(Option.builder("dh").longOpt("ecdh").desc("Do ECDH.").build());
        actions.addOption(Option.builder("dsa").longOpt("ecdsa").desc("Sign data with ECDSA.").hasArg().argName("data_file").optionalArg(true).build());
        opts.addOptionGroup(actions);

        OptionGroup size = new OptionGroup();
        size.addOption(Option.builder("b").longOpt("bit-size").desc("Set curve size.").hasArg().argName("b").build());
        size.addOption(Option.builder("a").longOpt("all").desc("Test all curve sizes.").build());
        opts.addOptionGroup(size);

        OptionGroup curve = new OptionGroup();
        curve.addOption(Option.builder("n").longOpt("named").desc("Use a named curve.").hasArg().argName("[cat/id|id|cat]").build());
        curve.addOption(Option.builder("c").longOpt("curve").desc("Use curve from file [curve_file] (field,a,b,gx,gy,r,k).").hasArg().argName("curve_file").build());
        curve.addOption(Option.builder("u").longOpt("custom").desc("Use a custom curve(applet-side embedded, SECG curves).").build());
        opts.addOptionGroup(curve);

        opts.addOption(Option.builder("fp").longOpt("prime-field").desc("Use prime field curve.").build());
        opts.addOption(Option.builder("f2m").longOpt("binary-field").desc("Use binary field curve.").build());

        OptionGroup pub = new OptionGroup();
        pub.addOption(Option.builder("npub").longOpt("named-public").desc("Use public key from KeyDB: [cat/id|cat|id]").hasArg().argName("[cat/id|id|cat]").build());
        pub.addOption(Option.builder("pub").longOpt("public").desc("Use public key from file [pubkey_file] (wx,wy).").hasArg().argName("pubkey_file").build());
        opts.addOptionGroup(pub);

        OptionGroup priv = new OptionGroup();
        priv.addOption(Option.builder("npriv").longOpt("named-private").desc("Use private key from KeyDB: [cat/id|id|cat]").hasArg().argName("[cat/id|id|cat]").build());
        priv.addOption(Option.builder("priv").longOpt("private").desc("Use private key from file [privkey_file] (s).").hasArg().argName("privkey_file").build());
        opts.addOptionGroup(priv);

        OptionGroup key = new OptionGroup();
        key.addOption(Option.builder("nk").longOpt("named-key").desc("Use keyPair from KeyDB: [cat/id|id|cat]").hasArg().argName("[cat/id|id|cat]").build());
        key.addOption(Option.builder("k").longOpt("key").desc("Use keyPair from file [key_file] (wx,wy,s).").hasArg().argName("key_file").build());
        opts.addOptionGroup(key);

        opts.addOption(Option.builder("o").longOpt("output").desc("Output into file [output_file].").hasArg().argName("output_file").build());
        opts.addOption(Option.builder("l").longOpt("log").desc("Log output into file [log_file].").hasArg().argName("log_file").optionalArg(true).build());

        opts.addOption(Option.builder("f").longOpt("fresh").desc("Generate fresh keys(set domain parameters before every generation).").build());
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

        optNamedCurve = cli.getOptionValue("named");
        optCustomCurve = cli.hasOption("custom");
        optCurveFile = cli.getOptionValue("curve");

        optNamedPublic = cli.getOptionValue("named-public");
        optPublic = cli.getOptionValue("public");

        optNamedPrivate = cli.getOptionValue("named-private");
        optPrivate = cli.getOptionValue("private");

        optNamedKey = cli.getOptionValue("named-key");
        optKey = cli.getOptionValue("key");
        if (cli.hasOption("log")) {
            optLog = cli.getOptionValue("log", String.format("ECTESTER_log_%d.log", System.currentTimeMillis() / 1000));
        }
        optOutput = cli.getOptionValue("output");
        optFresh = cli.hasOption("fresh");
        optSimulate = cli.hasOption("simulate");

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


        if (cli.hasOption("export")) {
            if (optPrimeField == optBinaryField) {
                System.err.print("Need to specify field with -fp or -f2m. (not both)");
                return false;
            }
            if (optKey != null || optPublic != null || optPrivate != null || optNamedKey != null || optNamedPublic != null || optNamedPrivate != null) {
                System.err.println("Keys should not be specified when exporting curve params.");
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
            if (optKey != null || optPublic != null || optPrivate != null || optNamedKey != null || optNamedPublic != null || optNamedPrivate != null) {
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

        } else if (cli.hasOption("ecdh")) {
            if (optPrimeField == optBinaryField) {
                System.err.print("Need to specify field with -fp or -f2m. (not both)");
                return false;
            }
            if (optAll) {
                System.err.println("You have to specify curve bit-size with -b");
                return false;
            }

        } else if (cli.hasOption("ecdsa")) {
            if (optPrimeField == optBinaryField) {
                System.err.print("Need to specify field with -fp or -f2m. (not both)");
                return false;
            }
            if (optAll) {
                System.err.println("You have to specify curve bit-size with -b");
                return false;
            }

            boolean hasPublic = (optPublic != null) || (optNamedPublic != null);
            boolean hasPrivate = (optPrivate != null) || (optNamedPrivate != null);
            boolean hasKey = (optKey != null) || (optNamedKey != null);
            if ((hasPublic) != (hasPrivate) && !hasKey) {
                System.err.println("You have cannot only specify a part of a keypair.");
                return false;
            }

            optECDSASign = cli.getOptionValue("ecdsa");
        }

        return true;
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
        //skip cofactor in domain export, since it doesnt need to be initialized for the key to be initialized.
        //and generally isn't initialized on cards with default domain params(TODO, check, is it assumed to be ==1?)
        short domain = (short) ((optPrimeField ? EC_Consts.PARAMETERS_DOMAIN_FP : EC_Consts.PARAMETERS_DOMAIN_F2M) ^ EC_Consts.PARAMETER_K);

        List<Response> sent = Command.sendAll(prepareKeyPair(ECTesterApplet.KEYPAIR_LOCAL, (short) optBits, keyClass));
        sent.add(new Command.Clear(cardManager, ECTesterApplet.KEYPAIR_LOCAL).send());
        sent.add(new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_LOCAL).send());
        Response.Export export = new Command.Export(cardManager, ECTesterApplet.KEYPAIR_LOCAL, EC_Consts.KEY_PUBLIC, domain).send();
        sent.add(export);

        systemOutLogger.println(Response.toString(sent));

        ECParams.writeFile(optOutput, ECParams.expand(export.getParams(), domain));
    }

    /**
     * Generates EC keyPairs and outputs them to output file.
     *
     * @throws CardException if APDU transmission fails
     * @throws IOException   if an IO error occurs when writing to key file.
     */
    private void generate() throws CardException, IOException {
        byte keyClass = optPrimeField ? KeyPair.ALG_EC_FP : KeyPair.ALG_EC_F2M;

        Command.sendAll(prepareKeyPair(ECTesterApplet.KEYPAIR_LOCAL, (short) optBits, keyClass));
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
     * @throws IOException
     * @throws CardException
     */
    private void test() throws IOException, CardException {
        List<Command> commands = new LinkedList<>();
        if (optAll) {
            if (optPrimeField) {
                //iterate over prime curve sizes used: EC_Consts.FP_SIZES
                for (short keyLength : EC_Consts.FP_SIZES) {
                    commands.addAll(testCurve(keyLength, KeyPair.ALG_EC_FP));
                }
            }
            if (optBinaryField) {
                //iterate over binary curve sizes used: EC_Consts.F2M_SIZES
                for (short keyLength : EC_Consts.F2M_SIZES) {
                    commands.addAll(testCurve(keyLength, KeyPair.ALG_EC_F2M));
                }
            }
        } else {
            if (optPrimeField) {
                commands.addAll(testCurve((short) optBits, KeyPair.ALG_EC_FP));
            }

            if (optBinaryField) {
                commands.addAll(testCurve((short) optBits, KeyPair.ALG_EC_F2M));
            }
        }
        List<Response> test = Command.sendAll(commands);
        systemOutLogger.println(Response.toString(test));
    }

    /**
     * Performs ECDH key exchange.
     *
     * @throws CardException if APDU transmission fails
     * @throws IOException   if an IO error occurs when writing to key file.
     */
    private void ecdh() throws IOException, CardException {
        byte keyClass = optPrimeField ? KeyPair.ALG_EC_FP : KeyPair.ALG_EC_F2M;
        List<Response> ecdh = Command.sendAll(prepareKeyPair(ECTesterApplet.KEYPAIR_BOTH, (short) optBits, keyClass));
        ecdh.addAll(Command.sendAll(prepareCurve(ECTesterApplet.KEYPAIR_BOTH, (short) optBits, keyClass)));

        if (optPublic != null || optPrivate != null || optKey != null) {
            ecdh.add(new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_LOCAL).send());
            ecdh.add(prepareKey(ECTesterApplet.KEYPAIR_REMOTE).send());
        } else {
            ecdh.add(new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_BOTH).send());
        }

        Response.ECDH perform = new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_TRUE, (byte) 0).send();
        ecdh.add(perform);
        systemOutLogger.println(Response.toString(ecdh));

        if (!perform.hasSecret()) {
            System.err.println("Couldn't obtain ECDH secret from card response.");
        } else {
            if (optOutput != null) {
                FileWriter out = new FileWriter(optOutput);
                out.write(Util.bytesToHex(perform.getSecret(), false));
                out.close();
            }
        }
    }

    /**
     * Performs ECDSA signature, on random or provided data.
     *
     * @throws CardException if APDU transmission fails
     * @throws IOException   if an IO error occurs when writing to key file.
     */
    private void ecdsa() throws CardException, IOException {
        byte keyClass = optPrimeField ? KeyPair.ALG_EC_FP : KeyPair.ALG_EC_F2M;
        List<Response> ecdsa = Command.sendAll(prepareKeyPair(ECTesterApplet.KEYPAIR_LOCAL, (short) optBits, keyClass));
        ecdsa.addAll(Command.sendAll(prepareCurve(ECTesterApplet.KEYPAIR_LOCAL, (short) optBits, keyClass)));

        Response keys;
        if (optKey != null || (optPublic != null && optPrivate != null)) {
            keys = prepareKey(ECTesterApplet.KEYPAIR_LOCAL).send();
        } else {
            keys = new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_LOCAL).send();
        }
        ecdsa.add(keys);

        //read file, if asked to sign
        byte[] data = null;
        if (optECDSASign != null) {
            File in = new File(optECDSASign);
            long len = in.length();
            if (len == 0) {
                throw new FileNotFoundException("File " + optECDSASign + " not found.");
            }
            data = Files.readAllBytes(in.toPath());
        }

        Response.ECDSA perform = new Command.ECDSA(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_TRUE, data).send();
        ecdsa.add(perform);
        systemOutLogger.println(Response.toString(ecdsa));

        if (!perform.hasSignature()) {
            System.err.println("Couldn't obtain ECDSA signature from card response.");
        } else {
            if (optOutput != null) {
                FileWriter out = new FileWriter(optOutput);
                out.write(Util.bytesToHex(perform.getSignature(), false));
                out.close();
            }
        }
    }

    /**
     * @param keyPair   which keyPair/s (local/remote) to allocate
     * @param keyLength key length to allocate
     * @param keyClass  key class to allocate
     * @return a list of Commands to send in order to prepare the keyPair.
     */
    private List<Command> prepareKeyPair(byte keyPair, short keyLength, byte keyClass) {
        List<Command> commands = new ArrayList<>();
        commands.add(new Command.Allocate(cardManager, keyPair, keyLength, keyClass));
        return commands;
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

        short domainParams = keyClass == KeyPair.ALG_EC_FP ? EC_Consts.PARAMETERS_DOMAIN_FP : EC_Consts.PARAMETERS_DOMAIN_F2M;
        if (optCustomCurve) {
            // Set custom curve (one of the SECG curves embedded applet-side)
            commands.add(new Command.Set(cardManager, keyPair, EC_Consts.getCurve(keyLength, keyClass), domainParams, EC_Consts.PARAMETERS_NONE, EC_Consts.CORRUPTION_NONE, null));
        } else if (optNamedCurve != null) {
            // Set a named curve.
            // parse optNamedCurve -> cat / id | cat | id
        } else if (optCurveFile != null) {
            // Set curve loaded from a file
            byte[] external = ECParams.flatten(domainParams, ECParams.readFile(optCurveFile));
            if (external == null) {
                throw new IOException("Couldn't read the curve file correctly.");
            }
            commands.add(new Command.Set(cardManager, keyPair, EC_Consts.CURVE_external, domainParams, EC_Consts.PARAMETERS_NONE, EC_Consts.CORRUPTION_NONE, external));
        } else {
            // Set default curve
            commands.add(new Command.Clear(cardManager, keyPair));
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
        if (optKey != null) {
            params |= EC_Consts.PARAMETERS_KEYPAIR;
            data = ECParams.flatten(EC_Consts.PARAMETERS_KEYPAIR, ECParams.readFile(optKey));
            if (data == null) {
                throw new IOException("Couldn't read the key file correctly.");
            }
        }

        if (optPublic != null) {
            params |= EC_Consts.PARAMETER_W;
            byte[] pubkey = ECParams.flatten(EC_Consts.PARAMETER_W, ECParams.readFile(optPublic));
            if (pubkey == null) {
                throw new IOException("Couldn't read the key file correctly.");
            }
            data = pubkey;
        }
        if (optPrivate != null) {
            params |= EC_Consts.PARAMETER_S;
            byte[] privkey = ECParams.flatten(EC_Consts.PARAMETER_S, ECParams.readFile(optPrivate));
            if (privkey == null) {
                throw new IOException("Couldn't read the key file correctly.");
            }
            data = Util.concatenate(data, privkey);
        }
        return new Command.Set(cardManager, keyPair, EC_Consts.CURVE_external, params, EC_Consts.PARAMETERS_NONE, EC_Consts.CORRUPTION_NONE, data);
    }

    /**
     * @param keyLength
     * @param keyClass
     * @return
     * @throws IOException
     */
    private List<Command> testCurve(short keyLength, byte keyClass) throws IOException {
        List<Command> commands = new LinkedList<>();
        commands.addAll(prepareKeyPair(ECTesterApplet.KEYPAIR_BOTH, keyLength, keyClass));
        commands.addAll(prepareCurve(ECTesterApplet.KEYPAIR_BOTH, keyLength, keyClass));
        commands.add(new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_BOTH));
        commands.add(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, (byte) 0));
        commands.add(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_FALSE, (byte) 1));
        commands.add(new Command.ECDSA(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_FALSE, null));
        return commands;
    }

    public static void main(String[] args) {
        ECTester app = new ECTester();
        app.run(args);
    }
}
