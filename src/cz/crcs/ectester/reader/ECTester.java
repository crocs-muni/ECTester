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
    private boolean optNamed = false;
    private String optCurve = null;
    private String optPublic = null;
    private String optPrivate = null;
    private String optKey = null;
    private String optLog = null;
    private String optOutput = null;
    private boolean optFresh = false;
    private boolean optSimulate = false;

    private int optGenerateAmount;
    private String optECDSASign;

    private Options opts = new Options();
    private static final String CLI_HEADER = "";
    private static final String CLI_FOOTER = "";


    private static final byte[] SELECT_ECTESTERAPPLET = {(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0a,
            (byte) 0x45, (byte) 0x43, (byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x65, (byte) 0x72, (byte) 0x30, (byte) 0x31};
    private static final byte[] AID = {(byte) 0x4C, (byte) 0x61, (byte) 0x62, (byte) 0x61, (byte) 0x6B, (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};
    private static final byte[] INSTALL_DATA = new byte[10];

    /*
    private static final byte[] ALLOCATE = {
            (byte) 0xB0,
            (byte) 0x5a, //INS  ALLOCATE
            (byte) 0x00, //P1   *byte keyPair
            (byte) 0x00, //P2
            (byte) 0x03, //LC
            (byte) 0x00, //DATA *short keyLength
            (byte) 0x00,
            (byte) 0x00  //     *byte keyClass
    };

    private static final byte[] SET = {
            (byte) 0xB0,
            (byte) 0x5B, //INS  SET
            (byte) 0x00, //P1   *byte keyPair
            (byte) 0x00, //P2   *byte export
            (byte) 0x06, //LC
            (byte) 0x00, //DATA *byte curve
            (byte) 0x00, //     *short params
            (byte) 0x00, //
            (byte) 0x00, //     *short corruptedParams
            (byte) 0x00, //
            (byte) 0x00  //     *byte corruptionType
            //     [short paramLength, byte[] param] for all params in params
    };

    private static final byte[] GENERATE = {
            (byte) 0xB0,
            (byte) 0x5C, //INS  GENERATE
            (byte) 0x00, //P1   *byte keyPair
            (byte) 0x00, //P2   *byte export
            (byte) 0x00  //LC
    };

    private static final byte[] ECDH = {
            (byte) 0xB0,
            (byte) 0x5D, //INS  ECDH
            (byte) 0x00, //P1   *byte keyPair
            (byte) 0x00, //P2   *byte export
            (byte) 0x01, //LC
            (byte) 0x00  //DATA *byte valid
    };

    private static final byte[] ECDSA = {
            (byte) 0xB0,
            (byte) 0x5E, //INS ECDSA
            (byte) 0x00, //P1   *byte keyPair
            (byte) 0x00, //P2   *byte export
            (byte) 0x00, //LC
            //DATA [*short dataLength, byte[] data]
    };
    */

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
            if (cli.hasOption("generate")) {
                generate();
            } else if (cli.hasOption("test")) {
                test();
            } else if (cli.hasOption("ecdh")) {
                ecdh();
            } else if (cli.hasOption("ecdsa")) {
                ecdsa();
            }

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
        } catch (ParseException | CardException pex) {
            System.err.println(pex.getMessage());
        } catch (NumberFormatException nfex) {
            System.err.println("Not a number. " + nfex.getMessage());
            nfex.printStackTrace(System.err);
        } catch (FileNotFoundException fnfe) {
            System.err.println("File " + fnfe.getMessage() + " not found.");
        } catch (IOException e) {
            e.printStackTrace();
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
         * -g / --generate [amount]
         * -t / --test
         * -dh / --ecdh
         * -dsa / --ecdsa [data_file]
         *
         * Options:
         * -b / --bit-size [b] // -a / --all
         * -fp / --prime-field
         * -f2m / --binary-field
         * -n / --named // -c / --curve [curve_file] field,a,b,gx,gy,r,k
         * --public [pubkey_file] wx,wy
         * --private [privkey_file] s
         * -k / --key [key_file] wx,wy,s
         * -o / --output [output_file]
         * -s / --simulate
         */
        OptionGroup actions = new OptionGroup();
        actions.setRequired(true);
        actions.addOption(Option.builder("h").longOpt("help").desc("Print help.").build());
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
        curve.addOption(Option.builder("n").longOpt("named").desc("Use a named curve.").build());
        curve.addOption(Option.builder("c").longOpt("curve").desc("Use curve from file [curve_file] (field,a,b,gx,gy,r,k).").hasArg().argName("curve_file").build());
        opts.addOptionGroup(curve);

        opts.addOption(Option.builder("fp").longOpt("prime-field").desc("Use prime field curve.").build());
        opts.addOption(Option.builder("f2m").longOpt("binary-field").desc("Use binary field curve.").build());

        opts.addOption(Option.builder("pub").longOpt("public").desc("Use public key from file [pubkey_file] (wx,wy).").hasArg().argName("pubkey_file").build());
        opts.addOption(Option.builder("priv").longOpt("private").desc("Use private key from file [privkey_file] (s).").hasArg().argName("privkey_file").build());
        opts.addOption(Option.builder("k").longOpt("key").desc("Use keyPair from file [key_file] (wx,wy,s).").hasArg().argName("key_file").build());

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
        optNamed = cli.hasOption("named");
        optCurve = cli.getOptionValue("curve");
        optPublic = cli.getOptionValue("public");
        optPrivate = cli.getOptionValue("private");
        optKey = cli.getOptionValue("key");
        if (cli.hasOption("log")) {
            optLog = cli.getOptionValue("log", String.format("ECTESTER_log_%d.log", System.currentTimeMillis() / 1000));
        }
        optOutput = cli.getOptionValue("output");
        optFresh = cli.hasOption("fresh");
        optSimulate = cli.hasOption("simulate");

        if (optKey != null && (optPublic != null || optPrivate != null)) {
            System.err.print("Can only specify the whole key with --key or pubkey and privkey with --public and --private.");
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

        if (cli.hasOption("generate")) {
            if (optPrimeField == optBinaryField) {
                System.err.print("Need to specify field with -fp or -f2m. (not both)");
                return false;
            }
            if (optKey != null || optPublic != null || optPrivate != null) {
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
            if ((optPublic == null) != (optPrivate == null)) {
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
        help.printHelp("ECTester.jar", CLI_HEADER, opts, CLI_FOOTER, true);
    }

    /**
     * Generates EC keyPairs and outputs them to output file.
     *
     * @throws CardException if APDU transmission fails
     * @throws IOException   if an IO error occurs when writing to key file.
     */
    private void generate() throws CardException, IOException {
        byte keyClass = optPrimeField ? KeyPair.ALG_EC_FP : KeyPair.ALG_EC_F2M;
        List<Response> prepare = Command.sendAll(prepareKeyPair(ECTesterApplet.KEYPAIR_LOCAL, (short) optBits, keyClass));
        prepare.addAll(Command.sendAll(prepareCurve(ECTesterApplet.KEYPAIR_LOCAL, (short) optBits, keyClass)));

        FileWriter keysFile = new FileWriter(optOutput);
        keysFile.write("index;time;pubW;privS\n");

        int generated = 0;
        int retry = 0;
        while (generated < optGenerateAmount || optGenerateAmount == 0) {
            if (optFresh) {
                Command.sendAll(prepareCurve(ECTesterApplet.KEYPAIR_LOCAL, (short) optBits, keyClass));
            }

            Command.Generate generate = new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_LOCAL, (byte) (ECTesterApplet.EXPORT_BOTH | ECTesterApplet.KEYPAIR_LOCAL));
            Response.Generate response = generate.send();
            long elapsed = response.getDuration();

            if (!response.successful()) {
                if (retry < 10) {
                    retry++;
                    continue;
                } else {
                    System.err.println("Keys could not be generated.");
                    break;
                }
            }
            systemOutLogger.println(response.toString());

            String pub = Util.bytesToHex(response.getPublic(ECTesterApplet.KEYPAIR_LOCAL), false);
            String priv = Util.bytesToHex(response.getPrivate(ECTesterApplet.KEYPAIR_LOCAL), false);
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
            Response local = new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_NONE).send();
            Response remote = prepareKey(ECTesterApplet.KEYPAIR_REMOTE).send();
            ecdh.add(local);
            ecdh.add(remote);
        } else {
            Response both = new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_BOTH, ECTesterApplet.EXPORT_NONE).send();
            ecdh.add(both);
        }

        Response.ECDH perform = new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_ECDH, (byte) 0).send();
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
            keys = new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_NONE).send();
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

        Response.ECDSA perform = new Command.ECDSA(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_SIG, data).send();
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
        if (optNamed) {
            // Set named curve (one of the SECG curves embedded applet-side)
            commands.add(new Command.Set(cardManager, keyPair, ECTesterApplet.EXPORT_NONE, EC_Consts.getCurve(keyLength, keyClass), domainParams, EC_Consts.PARAMETERS_NONE, EC_Consts.CORRUPTION_NONE, null));
        } else if (optCurve != null) {
            // Set curve loaded from a file
            byte[] external = ParamReader.flatten(domainParams, ParamReader.readFile(optCurve));
            if (external == null) {
                throw new IOException("Couldn't read the curve file correctly.");
            }
            commands.add(new Command.Set(cardManager, keyPair, ECTesterApplet.EXPORT_NONE, EC_Consts.CURVE_external, domainParams, EC_Consts.PARAMETERS_NONE, EC_Consts.CORRUPTION_NONE, external));
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
            data = ParamReader.flatten(EC_Consts.PARAMETERS_KEYPAIR, ParamReader.readFile(optKey));
        }

        if (optPublic != null) {
            params |= EC_Consts.PARAMETER_W;
            data = ParamReader.flatten(EC_Consts.PARAMETER_W, ParamReader.readFile(optPublic));
        }
        if (optPrivate != null) {
            params |= EC_Consts.PARAMETER_S;
            data = Util.concatenate(data, ParamReader.flatten(EC_Consts.PARAMETER_S, ParamReader.readFile(optPrivate)));
        }

        if (data == null && params != EC_Consts.PARAMETERS_NONE) {
            /*
            TODO: this is not correct, in case (optPublic != null) and (optPrivate != null),
            only one can actually load(return not null from ParamReader.flatten) and an exception will not be thrown
             */
            throw new IOException("Couldn't read the key file correctly.");
        }
        return new Command.Set(cardManager, keyPair, ECTesterApplet.EXPORT_NONE, EC_Consts.CURVE_external, params, EC_Consts.PARAMETERS_NONE, EC_Consts.CORRUPTION_NONE, data);
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
        commands.add(new Command.Generate(cardManager, ECTesterApplet.KEYPAIR_BOTH, ECTesterApplet.EXPORT_NONE));
        commands.add(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_NONE, (byte) 0));
        commands.add(new Command.ECDH(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.KEYPAIR_REMOTE, ECTesterApplet.EXPORT_NONE, (byte) 1));
        commands.add(new Command.ECDSA(cardManager, ECTesterApplet.KEYPAIR_LOCAL, ECTesterApplet.EXPORT_NONE, null));
        return commands;
    }

    public static void main(String[] args) {
        ECTester app = new ECTester();
        app.run(args);
    }
}
