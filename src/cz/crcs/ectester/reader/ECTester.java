package cz.crcs.ectester.reader;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import javacard.security.KeyPair;
import org.apache.commons.cli.*;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;

/**
 * @author Petr Svenda petr@svenda.com
 * @author Jan Jancar johny@neuromancer.sk
 */
public class ECTester {

    private CardMngr cardManager = null;
    private DirtyLogger systemOutLogger = null;
    private FileOutputStream outputFile = null;

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
            (byte) 0x00, //P1   *byte keypair
            (byte) 0x00, //P2
            (byte) 0x03, //LC
            (byte) 0x00, //DATA *short keyLength
            (byte) 0x00,
            (byte) 0x00  //     *byte keyClass
    };

    private static final byte[] SET = {
            (byte) 0xB0,
            (byte) 0x5B, //INS  SET
            (byte) 0x00, //P1   *byte keypair
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
            (byte) 0x00, //P1   *byte keypair
            (byte) 0x00, //P2   *byte export
            (byte) 0x00  //LC
    };

    private static final byte[] ECDH = {
            (byte) 0xB0,
            (byte) 0x5D, //INS  ECDH
            (byte) 0x00, //P1   *byte keypair
            (byte) 0x00, //P2   *byte export
            (byte) 0x01, //LC
            (byte) 0x00  //DATA *byte valid
    };

    private static final byte[] ECDSA = {
            (byte) 0xB0,
            (byte) 0x5E, //INS ECDSA
            (byte) 0x00, //P1   *byte keypair
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
        } catch (AlreadySelectedException asex) {
            System.err.println(asex.getMessage());
        } catch (ParseException | CardException pex) {
            pex.printStackTrace();
        } catch (NumberFormatException nfex) {
            System.err.println("Not a number. " + nfex.getMessage());
            nfex.printStackTrace(System.err);
        } catch (FileNotFoundException fnfe) {
            System.err.println("File " + fnfe.getMessage() + " not found.");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

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
         * -b / --bit-size [b] / -a / --all
         * -fp / --prime-field
         * -f2m / --binary-field
         * -n / --named
         * -c / --curve [curve_file] field,a,b,gx,gy,r,k
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

        opts.addOption(Option.builder("fp").longOpt("prime-field").desc("Use prime field curve.").build());
        opts.addOption(Option.builder("f2m").longOpt("binary-field").desc("Use binary field curve.").build());
        opts.addOption(Option.builder("n").longOpt("named").desc("Use a named curve.").build());
        opts.addOption(Option.builder("c").longOpt("curve").desc("Use curve from file [curve_file] (field,a,b,gx,gy,r,k).").hasArg().argName("curve_file").build());
        opts.addOption(Option.builder("pub").longOpt("public").desc("Use public key from file [pubkey_file] (wx,wy).").hasArg().argName("pubkey_file").build());
        opts.addOption(Option.builder("priv").longOpt("private").desc("Use private key from file [privkey_file] (s).").hasArg().argName("privkey_file").build());
        opts.addOption(Option.builder("k").longOpt("key").desc("Use keypair from file [key_file] (wx,wy,s).").hasArg().argName("key_file").build());
        opts.addOption(Option.builder("o").longOpt("output").desc("Output into file [output_file].").hasArg().argName("output_file").build());
        opts.addOption(Option.builder("l").longOpt("log").desc("Log output into file [log_file].").hasArg().argName("log_file").optionalArg(true).build());
        opts.addOption(Option.builder("s").longOpt("simulate").desc("Simulate a card with jcardsim instead of using a terminal.").build());

        CommandLineParser parser = new DefaultParser();
        return parser.parse(opts, args);
    }

    /**
     * Reads and validates options.
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
        optSimulate = cli.hasOption("simulate");

        if (optKey != null && (optPublic != null || optPrivate != null)) {
            System.err.print("Can only specify the whole key with --key or pubkey and privkey with --public and --private.");
            return false;
        }
        if (optBits < 0) {
            System.err.println("Bit-size must not be negative.");
            return false;
        }
        if (optNamed && optCurve != null) {
            System.err.println("Can only specify a named curve with --named or an external curve with --curve. (not both)");
            return false;
        }
        if (optBits == 0 || optAll) {
            System.err.println("You have to specify curve bit-size.");
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
        } else if (cli.hasOption("ecdsa")) {
            optECDSASign = cli.getOptionValue("ecdsa");
        }

        return true;
    }

    /**
     * Prints help.
     */
    private void help() {
        HelpFormatter help = new HelpFormatter();
        help.printHelp("ECTester.jar", CLI_HEADER, opts, CLI_FOOTER);
    }

    /**
     * Generates EC keypairs and outputs them to log.
     */
    private void generate() throws CardException, IOException {
        /////
        short keyLength = (short) optBits;
        byte keyClass = optPrimeField ? KeyPair.ALG_EC_FP : KeyPair.ALG_EC_F2M;
        short params = optPrimeField ? EC_Consts.PARAMETERS_DOMAIN_FP : EC_Consts.PARAMETERS_DOMAIN_F2M;

        cmdAllocate(ECTesterApplet.KEYPAIR_LOCAL, keyLength, keyClass);

        if (optNamed) {
            cmdSet(ECTesterApplet.KEYPAIR_LOCAL, (byte) 0, EC_Consts.getCurve(keyLength, keyClass), params, EC_Consts.PARAMETERS_NONE, EC_Consts.CORRUPTION_NONE, null);
        } else if (optCurve != null) {
            byte[] external = ParamReader.flatten(params, ParamReader.readFile(optCurve));
            cmdSet(ECTesterApplet.KEYPAIR_LOCAL, (byte) 0, EC_Consts.CURVE_external, params, EC_Consts.PARAMETERS_NONE, EC_Consts.CORRUPTION_NONE, external);
        }
        /////

        FileWriter keysFile = new FileWriter(optOutput);
        keysFile.write("index;time;pubW;privS\n");

        int generated = 0;
        int retry = 0;
        while (generated < optGenerateAmount || optGenerateAmount == 0) {
            long elapsed = -System.nanoTime();
            ResponseAPDU response = cmdGenerate(ECTesterApplet.KEYPAIR_LOCAL, (byte) (ECTesterApplet.EXPORT_BOTH | ECTesterApplet.KEYPAIR_LOCAL));
            elapsed += System.nanoTime();

            byte[] bytes = response.getData();
            if (bytes.length <= 2) {
                //error, retry 10 times
                if (retry < 10) {
                    retry++;
                } else {
                    System.err.println("Keys could not be generated.");
                    break;
                }
            } else {
                short publicLength = Util.getShort(bytes, 2);
                String pubkey = Util.bytesToHex(bytes, 4, publicLength, false);
                short privateLength = Util.getShort(bytes, 4 + publicLength);
                String privkey = Util.bytesToHex(bytes, 6 + publicLength, privateLength, false);

                keysFile.write(String.format("%d;%d;%s;%s\n", generated, elapsed / 1000000, pubkey, privkey));
                keysFile.flush();
                generated++;
            }
        }
        keysFile.close();
    }

    /**
     *
     */
    private void test() {
        //TODO
        //  allocate
        //  set custom
        //  generate
        //  ecdh local, local, valid
        //  ecdh local, local, invalid
        //  ecdsa local, local, 00?

    }

    /**
     *
     */
    private void ecdh() {
        //TODO
        //allocate local + remote
        //set curve if specified
        //
    }

    /**
     */
    private void ecdsa() {
        //TODO
    }

    /**
     * Sends the INS_ALLOCATE instruction to the card/simulation.
     *
     * @param keypair
     * @param keyLength
     * @param keyClass
     * @return card response
     * @throws CardException
     */
    private ResponseAPDU cmdAllocate(byte keypair, short keyLength, byte keyClass) throws CardException {
        byte[] data = new byte[]{0, 0, keyClass};
        Util.setShort(data, 0, keyLength);

        CommandAPDU allocate = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_ALLOCATE, keypair, 0x00, data);
        return cardManager.send(allocate);
    }

    /**
     * Sends the INS_SET instruction to the card/simulation.
     *
     * @param keypair
     * @param export
     * @param curve
     * @param params
     * @param corrupted
     * @param corruption
     * @param external
     * @return card response
     * @throws CardException
     */
    private ResponseAPDU cmdSet(byte keypair, byte export, byte curve, short params, short corrupted, byte corruption, byte[] external) throws CardException {
        int len = external != null ? 6 + 2 + external.length : 6;
        byte[] data = new byte[len];
        data[0] = curve;
        Util.setShort(data, 1, params);
        Util.setShort(data, 3, corrupted);
        data[5] = corruption;
        if (external != null) {
            System.arraycopy(external, 0, data, 6, external.length);
        }

        CommandAPDU set = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_SET, keypair, export, data);
        return cardManager.send(set);
    }

    /**
     * Sends the INS_GENERATE instruction to the card/simulation.
     *
     * @param keypair
     * @param export
     * @return card response
     */
    private ResponseAPDU cmdGenerate(byte keypair, byte export) throws CardException {
        CommandAPDU generate = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_GENERATE, keypair, export);
        return cardManager.send(generate);
    }

    /**
     * Sends the INS_ECDH instruction to the card/simulation.
     *
     * @param keypair
     * @param export
     * @param valid
     * @return card response
     * @throws CardException
     */
    private ResponseAPDU cmdECDH(byte keypair, byte export, byte valid) throws CardException {
        byte[] data = new byte[1];
        data[0] = valid;

        CommandAPDU ecdh = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_ECDH, keypair, export, data);
        return cardManager.send(ecdh);
    }

    /**
     * Sends the INS_ECDSA instruction to the card/simulation.
     *
     * @param keypair
     * @param export
     * @param raw
     * @return card response
     */
    private ResponseAPDU cmdECDSA(byte keypair, byte export, byte[] raw) throws CardException {
        int len = raw != null ? raw.length : 0;
        byte[] data = new byte[2 + len];
        Util.setShort(data, 0, (short) len);
        if (raw != null) {
            System.arraycopy(raw, 0, data, 2, len);
        }

        CommandAPDU ecdsa = new CommandAPDU(ECTesterApplet.CLA_ECTESTERAPPLET, ECTesterApplet.INS_ECDSA, keypair, export, data);
        return cardManager.send(ecdsa);
    }

    public static void main(String[] args) {
        ECTester app = new ECTester();
        app.run(args);
    }
}
