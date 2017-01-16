package simpleapdu;

import applets.EC_Consts;
import applets.SimpleECCApplet;
import javacard.framework.ISO7816;
import javacard.security.CryptoException;
import javacard.security.KeyPair;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import javax.smartcardio.ResponseAPDU;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;


/**
 * @author Petr Svenda petr@svenda.com
 */
public class SimpleAPDU {
    private CardMngr cardManager = new CardMngr();
    private DirtyLogger systemOutLogger = null;

    private CommandLineParser cliParser = new DefaultParser();
    private Options opts = new Options();
    private static final String cliHeader = "";
    private static final String cliFooter = "";

    private final static byte SELECT_ECTESTERAPPLET[] = {(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0a,
            (byte) 0x45, (byte) 0x43, (byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x65, (byte) 0x72, (byte) 0x30, (byte) 0x31};

    private static final byte TESTECSUPPORTALL_FP[] = {(byte) 0xB0, (byte) 0x5E, (byte) 0x00, (byte) 0x00, (byte) 0x00};
    private static final byte TESTECSUPPORTALL_F2M[] = {(byte) 0xB0, (byte) 0x5F, (byte) 0x00, (byte) 0x00, (byte) 0x00};
    private static final byte TESTECSUPPORT_GIVENALG[] = {(byte) 0xB0, (byte) 0x71, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x00, (byte) 0x00, (byte) 0x00};
    private static final short TESTECSUPPORT_ALG_OFFSET = 5;
    private static final short TESTECSUPPORT_KEYLENGTH_OFFSET = 6;

    private static final byte TESTECSUPPORTALL_LASTUSEDPARAMS[] = {(byte) 0xB0, (byte) 0x40, (byte) 0x00, (byte) 0x00, (byte) 0x00};

    private static final byte TESTECSUPPORTALL_FP_KEYGEN_INVALIDCURVEB[] = {(byte) 0xB0, (byte) 0x70, (byte) 0x00, (byte) 0x00, (byte) 0x05, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
    private static final short INVALIDCURVEB_NUMREPEATS_OFFSET = 5;
    private static final short INVALIDCURVEB_CORRUPTIONTYPE_OFFSET = 7;
    private static final short INVALIDCURVEB_REWINDONSUCCESS_OFFSET = 9;

    private static final byte TESTECSUPPORT_GENERATEECCKEY[] = {(byte) 0xB0, (byte) 0x5a, (byte) 0x00, (byte) 0x00, (byte) 0x04, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
    private static final short GENERATEECKEY_ALG_OFFSET = 5;
    private static final short GENERATEECKEY_KEYLENGTH_OFFSET = 6;
    private static final short GENERATEECKEY_ANOMALOUS_OFFSET = 8;


    public void run(String[] args) {
        try {
            //parse cmd args
            CommandLine cli = parseArgs(args);

            //byte[] installData = new byte[10];
            //byte[] AID = {(byte) 0x4C, (byte) 0x61, (byte) 0x62, (byte) 0x61, (byte) 0x6B, (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};
            //cardManager.prepareLocalSimulatorApplet(AID, installData, SimpleECCApplet.class);

            //do stuff
            if (cli.hasOption("help")) {
                HelpFormatter help = new HelpFormatter();
                help.printHelp("SimpleAPDU", cliHeader, opts, cliFooter);
            } else {
                //open log(only when actually doing something)
                String logFileName = cli.getOptionValue("output-file", String.format("ECTESTER_log_%d.log", System.currentTimeMillis()));
                FileOutputStream stdoutStream = new FileOutputStream(logFileName);
                systemOutLogger = new DirtyLogger(stdoutStream, true);

                boolean fp = cli.hasOption("fp");
                boolean f2m = cli.hasOption("f2m");
                if (!fp && !f2m) {
                    fp = true;
                    f2m = true;
                }
                int genAmount = Integer.parseInt(cli.getOptionValue("generate", "0"));
                int keyLength = Integer.parseInt(cli.getOptionValue("b", "192"));

                if (cli.hasOption("generate")) {
                    //generate EC keys
                    if (fp) {
                        generateECKeys(genAmount, KeyPair.ALG_EC_FP, (short) keyLength, cli.hasOption("anomalous"));
                    }
                    if (f2m) {
                        generateECKeys(genAmount, KeyPair.ALG_EC_F2M, (short) keyLength, cli.hasOption("anomalous"));
                    }
                } else if (cli.hasOption("test")) {
                    if (cli.hasOption("bit-length")) {
                        //test only one bitsize
                        if (fp) {
                            testSupportECFp((short) keyLength);
                        }
                        if (f2m) {
                            testSupportECFp((short) keyLength);
                        }
                    } else {
                        //test default bit sizes
                        testSupportECAll(fp, f2m);
                        testFPkeyGen((short) 10, EC_Consts.CORRUPTION_ONEBYTERANDOM, true);
                    }
                } else {
                    systemOutLogger.println("You need to specify one of -t / -g [num] commands.");
                }

                //close log
                systemOutLogger.close();
            }

            //disconnect
            cardManager.DisconnectFromCard();
        } catch (Exception ex) {
            if (systemOutLogger != null) {
                systemOutLogger.println("Exception : " + ex);
            }
        }
    }

    private CommandLine parseArgs(String[] args) throws ParseException {

        opts.addOption("h", "help", false, "show this help");
        opts.addOption(Option.builder("g")
                .longOpt("generate")
                .hasArg()
                .optionalArg(true)
                .argName("num")
                .desc("generate EC keys").build());
        opts.addOption("t", "test", false, "test EC support (default)");
        opts.addOption(Option.builder("b")
                .longOpt("bit-length")
                .hasArg()
                .argName("bits")
                .desc("set EC bit size").build());
        opts.addOption("f2m", "use EC over binary-fields");
        opts.addOption("fp", "user EC over prime-fields (default)");
        opts.addOption("s", "anomalous", false, "generate anomalous (non-prime order, small pubkey order) curves");
        opts.addOption(Option.builder("o")
                .longOpt("output-file")
                .hasArg()
                .argName("file")
                .desc("output file to log to").build());
        return cliParser.parse(opts, args);
    }

    static short getShort(byte[] array, int offset) {
        return (short) (((array[offset] & 0xFF) << 8) | (array[offset + 1] & 0xFF));
    }

    static void setShort(byte[] array, int offset, short value) {
        array[offset + 1] = (byte) (value & 0xFF);
        array[offset] = (byte) ((value >> 8) & 0xFF);
    }

    private boolean ReconnnectToCard() throws Exception {
        if (cardManager.isConnected()) {
            cardManager.DisconnectFromCard();
        }

        boolean result = cardManager.ConnectToCard();
        if (result) {
            // Select our application on card
            cardManager.sendAPDU(SELECT_ECTESTERAPPLET);
        }
        return result;
    }

    private void testFPkeyGen(short numRepeats, short corruptionType, boolean bRewind) throws Exception {
        byte[] apdu = Arrays.copyOf(TESTECSUPPORTALL_FP_KEYGEN_INVALIDCURVEB, TESTECSUPPORTALL_FP_KEYGEN_INVALIDCURVEB.length);
        setShort(apdu, INVALIDCURVEB_NUMREPEATS_OFFSET, numRepeats);
        setShort(apdu, INVALIDCURVEB_CORRUPTIONTYPE_OFFSET, corruptionType);
        apdu[INVALIDCURVEB_REWINDONSUCCESS_OFFSET] = bRewind ? (byte) 1 : (byte) 0;

        ReconnnectToCard();
        ResponseAPDU resp_fp_keygen = cardManager.sendAPDU(apdu);
        ResponseAPDU resp_keygen_params = cardManager.sendAPDU(TESTECSUPPORTALL_LASTUSEDPARAMS);
        PrintECKeyGenInvalidCurveB(resp_fp_keygen);
        PrintECKeyGenInvalidCurveB_lastUserParams(resp_keygen_params);
    }

    private void testSupportECGivenAlg(short keyLength, byte keyClass) throws Exception {
        byte[] apdu = Arrays.copyOf(TESTECSUPPORT_GIVENALG, TESTECSUPPORT_GIVENALG.length);
        apdu[TESTECSUPPORT_ALG_OFFSET] = keyClass;
        setShort(apdu, TESTECSUPPORT_KEYLENGTH_OFFSET, keyLength);

        ReconnnectToCard();
        ResponseAPDU resp = cardManager.sendAPDU(apdu);
        //byte[] resp = cardManager.sendAPDUSimulator(apdu);
        PrintECSupport(resp);
    }

    private void testSupportECFp(short keyLength) throws Exception {
        testSupportECGivenAlg(keyLength, KeyPair.ALG_EC_FP);
    }

    private void testSupportECF2m(short keyLength) throws Exception {
        testSupportECGivenAlg(keyLength, KeyPair.ALG_EC_F2M);
    }

    private void testSupportECAll(boolean testFp, boolean testF2m) throws Exception {
        if (testFp) {
            testSupportECFp((short) 128);
            testSupportECFp((short) 192);
            testSupportECFp((short) 224);
            testSupportECFp((short) 256);
            testSupportECFp((short) 384);
            testSupportECFp((short) 521);
        }

        if (testF2m) {
            testSupportECF2m((short) 113);
            testSupportECF2m((short) 131);
            testSupportECF2m((short) 163);
            testSupportECF2m((short) 193);
        }
    }

    private void generateECKeys(int amount, byte keyClass, short keyLength, boolean anomalous) throws Exception {
        if (cardManager.ConnectToCardSelect()) {
            cardManager.sendAPDU(SELECT_ECTESTERAPPLET);

            String keyFileName = String.format("ECKEYS_%s_%d.log", keyClass == KeyPair.ALG_EC_FP ? "fp" : "f2m", System.currentTimeMillis());
            FileOutputStream keysFile = new FileOutputStream(keyFileName);

            String message = "index;time;pubW;privS\n";
            keysFile.write(message.getBytes());
            byte[] gatherKeyAPDU = Arrays.copyOf(TESTECSUPPORT_GENERATEECCKEY, TESTECSUPPORT_GENERATEECCKEY.length);
            // Prepare keypair object
            gatherKeyAPDU[ISO7816.OFFSET_P1] = SimpleECCApplet.P1_SETCURVE;
            gatherKeyAPDU[GENERATEECKEY_ALG_OFFSET] = keyClass;
            setShort(gatherKeyAPDU, GENERATEECKEY_KEYLENGTH_OFFSET, keyLength);
            gatherKeyAPDU[GENERATEECKEY_ANOMALOUS_OFFSET] = anomalous ? (byte) 1 : (byte) 0;

            ResponseAPDU respGather = cardManager.sendAPDU(gatherKeyAPDU);
            if (respGather.getSW() != ISO7816.SW_NO_ERROR) {
                systemOutLogger.println(String.format("Card error: %x", respGather.getSW()));
                keysFile.close();
                return;
            }

            // Generate new keypair
            gatherKeyAPDU[ISO7816.OFFSET_P1] = SimpleECCApplet.P1_GENERATEKEYPAIR;
            int counter = 0;
            while (true) {
                counter++;
                long elapsed = -System.nanoTime();
                respGather = cardManager.sendAPDU(gatherKeyAPDU);
                elapsed += System.nanoTime();

                if (respGather.getSW() != ISO7816.SW_NO_ERROR) {
                    systemOutLogger.println(String.format("Card error: %x", respGather.getSW()));
                    break;
                }
                byte[] data = respGather.getData();
                int offset = 0;
                String pubKeyW = "";
                String privKeyS = "";
                if (data[offset] == EC_Consts.TAG_ECPUBKEY) {
                    offset++;
                    short len = getShort(data, offset);
                    offset += 2;
                    pubKeyW = CardMngr.bytesToHex(data, offset, len, false);
                    offset += len;
                }
                if (data[offset] == EC_Consts.TAG_ECPRIVKEY) {
                    offset++;
                    short len = getShort(data, offset);
                    offset += 2;
                    privKeyS = CardMngr.bytesToHex(data, offset, len, false);
                    offset += len;
                }

                message = String.format("%d;%d;%s;%s\n", counter, elapsed / 1000000, pubKeyW, privKeyS);
                keysFile.write(message.getBytes());

                this.systemOutLogger.flush();
                keysFile.flush();

                //stop when we have enough keys, go on forever with 0
                if (counter >= amount && amount != 0)
                    break;
            }
            keysFile.close();
        }
    }

    static String getPrintError(short code) {
        if (code == ISO7816.SW_NO_ERROR) {
            return "OK\t(0x9000)";
        } else {
            String codeStr = "unknown";
            if (code == CryptoException.ILLEGAL_VALUE) {
                codeStr = "ILLEGAL_VALUE";
            }
            if (code == CryptoException.UNINITIALIZED_KEY) {
                codeStr = "UNINITIALIZED_KEY";
            }
            if (code == CryptoException.NO_SUCH_ALGORITHM) {
                codeStr = "NO_SUCH_ALG";
            }
            if (code == CryptoException.INVALID_INIT) {
                codeStr = "INVALID_INIT";
            }
            if (code == CryptoException.ILLEGAL_USE) {
                codeStr = "ILLEGAL_USE";
            }
            if (code == SimpleECCApplet.SW_SKIPPED) {
                codeStr = "skipped";
            }
            if (code == SimpleECCApplet.SW_KEYPAIR_GENERATED_INVALID) {
                codeStr = "SW_KEYPAIR_GENERATED_INVALID";
            }
            if (code == SimpleECCApplet.SW_INVALID_CORRUPTION_TYPE) {
                codeStr = "SW_INVALID_CORRUPTION_TYPE";
            }
            if (code == SimpleECCApplet.SW_SIG_VERIFY_FAIL) {
                codeStr = "SW_SIG_VERIFY_FAIL";
            }
            return String.format("fail\t(%s,\t0x%4x)", codeStr, code);
        }
    }

    enum ExpResult {
        SHOULD_SUCCEED,
        MAY_FAIL,
        MUST_FAIL
    }

    private int VerifyPrintResult(String message, byte expectedTag, byte[] buffer, int bufferOffset, ExpResult expRes) {
        if (bufferOffset >= buffer.length) {
            systemOutLogger.println("   No more data returned");
        } else {
            if (buffer[bufferOffset] != expectedTag) {
                systemOutLogger.println("   ERROR: mismatched tag");
                assert (buffer[bufferOffset] == expectedTag);
            }
            bufferOffset++;
            short resCode = getShort(buffer, bufferOffset);
            bufferOffset += 2;

            boolean bHiglight = false;
            if ((expRes == ExpResult.MUST_FAIL) && (resCode == ISO7816.SW_NO_ERROR)) {
                bHiglight = true;
            }
            if ((expRes == ExpResult.SHOULD_SUCCEED) && (resCode != ISO7816.SW_NO_ERROR)) {
                bHiglight = true;
            }
            if (bHiglight) {
                systemOutLogger.println(String.format("!! %-53s%s", message, getPrintError(resCode)));
            } else {
                systemOutLogger.println(String.format("   %-53s%s", message, getPrintError(resCode)));
            }
        }
        return bufferOffset;
    }

    private void PrintECSupport(ResponseAPDU resp) {
        PrintECSupport(resp.getData());
    }

    private void PrintECSupport(byte[] buffer) {
        systemOutLogger.println();
        systemOutLogger.println("### Test for support and with valid and invalid EC curves");
        int bufferOffset = 0;
        while (bufferOffset < buffer.length) {
            assert (buffer[bufferOffset] == SimpleECCApplet.ECTEST_SEPARATOR);
            bufferOffset++;
            String ecType = "unknown";
            if (buffer[bufferOffset] == KeyPair.ALG_EC_FP) {
                ecType = "ALG_EC_FP";
            }
            if (buffer[bufferOffset] == KeyPair.ALG_EC_F2M) {
                ecType = "ALG_EC_F2M";
            }
            systemOutLogger.println(String.format("%-56s%s", "EC type:", ecType));
            bufferOffset++;
            short keyLen = getShort(buffer, bufferOffset);
            systemOutLogger.println(String.format("%-56s%d bits", "EC key length (bits):", keyLen));
            bufferOffset += 2;

            bufferOffset = VerifyPrintResult("KeyPair object allocation:", SimpleECCApplet.ECTEST_ALLOCATE_KEYPAIR, buffer, bufferOffset, ExpResult.SHOULD_SUCCEED);
            bufferOffset = VerifyPrintResult("Generate key with def curve (fails if no def):", SimpleECCApplet.ECTEST_GENERATE_KEYPAIR_DEFCURVE, buffer, bufferOffset, ExpResult.MAY_FAIL);
            bufferOffset = VerifyPrintResult("Set valid custom curve:", SimpleECCApplet.ECTEST_SET_VALIDCURVE, buffer, bufferOffset, ExpResult.SHOULD_SUCCEED);
            bufferOffset = VerifyPrintResult("Generate key with valid curve:", SimpleECCApplet.ECTEST_GENERATE_KEYPAIR_CUSTOMCURVE, buffer, bufferOffset, ExpResult.SHOULD_SUCCEED);
            bufferOffset = VerifyPrintResult("ECDH agreement with valid point:", SimpleECCApplet.ECTEST_ECDH_AGREEMENT_VALID_POINT, buffer, bufferOffset, ExpResult.SHOULD_SUCCEED);
            bufferOffset = VerifyPrintResult("ECDH agreement with invalid point (fail is good):", SimpleECCApplet.ECTEST_ECDH_AGREEMENT_INVALID_POINT, buffer, bufferOffset, ExpResult.MUST_FAIL);
            bufferOffset = VerifyPrintResult("ECDSA signature on random data:", SimpleECCApplet.ECTEST_ECDSA_SIGNATURE, buffer, bufferOffset, ExpResult.SHOULD_SUCCEED);
            bufferOffset = VerifyPrintResult("Set anomalous custom curve (may fail):", SimpleECCApplet.ECTEST_SET_ANOMALOUSCURVE, buffer, bufferOffset, ExpResult.MAY_FAIL);
            bufferOffset = VerifyPrintResult("Generate key with anomalous curve (may fail):", SimpleECCApplet.ECTEST_GENERATE_KEYPAIR_ANOMALOUSCURVE, buffer, bufferOffset, ExpResult.MAY_FAIL);
            bufferOffset = VerifyPrintResult("ECDH agreement with small order point (fail is good):", SimpleECCApplet.ECTEST_ECDH_AGREEMENT_SMALL_DEGREE_POINT, buffer, bufferOffset, ExpResult.MUST_FAIL);
            bufferOffset = VerifyPrintResult("Set invalid custom curve (may fail):", SimpleECCApplet.ECTEST_SET_INVALIDCURVE, buffer, bufferOffset, ExpResult.MAY_FAIL);
            bufferOffset = VerifyPrintResult("Generate key with invalid curve (fail is good):", SimpleECCApplet.ECTEST_GENERATE_KEYPAIR_INVALIDCUSTOMCURVE, buffer, bufferOffset, ExpResult.MUST_FAIL);
            bufferOffset = VerifyPrintResult("Set invalid field (may fail):", SimpleECCApplet.ECTEST_SET_INVALIDFIELD, buffer, bufferOffset, ExpResult.MAY_FAIL);
            bufferOffset = VerifyPrintResult("Generate key with invalid field (fail si good):", SimpleECCApplet.ECTEST_GENERATE_KEYPAIR_INVALIDFIELD, buffer, bufferOffset, ExpResult.MUST_FAIL);

            systemOutLogger.println();
        }
    }

    private void PrintECKeyGenInvalidCurveB(ResponseAPDU resp) {
        PrintECKeyGenInvalidCurveB(resp.getData());
    }

    private void PrintECKeyGenInvalidCurveB(byte[] buffer) {
        systemOutLogger.println();
        systemOutLogger.println("### Test for computation with invalid parameter B for EC curve");
        int bufferOffset = 0;
        while (bufferOffset < buffer.length) {
            assert (buffer[bufferOffset] == SimpleECCApplet.ECTEST_SEPARATOR);
            bufferOffset++;
            String ecType = "unknown";
            if (buffer[bufferOffset] == KeyPair.ALG_EC_FP) {
                ecType = "ALG_EC_FP";
            }
            if (buffer[bufferOffset] == KeyPair.ALG_EC_F2M) {
                ecType = "ALG_EC_F2M";
            }
            systemOutLogger.println(String.format("%-53s%s", "EC type:", ecType));
            bufferOffset++;
            short keyLen = getShort(buffer, bufferOffset);
            systemOutLogger.println(String.format("%-53s%d bits", "EC key length (bits):", keyLen));
            bufferOffset += 2;

            short numRepeats = getShort(buffer, bufferOffset);
            bufferOffset += 2;
            systemOutLogger.println(String.format("%-53s%d times", "Executed repeats before unexpected error: ", numRepeats));

            bufferOffset = VerifyPrintResult("KeyPair object allocation:", SimpleECCApplet.ECTEST_ALLOCATE_KEYPAIR, buffer, bufferOffset, ExpResult.SHOULD_SUCCEED);
            while (bufferOffset < buffer.length) {
                bufferOffset = VerifyPrintResult("Set invalid custom curve:", SimpleECCApplet.ECTEST_SET_INVALIDCURVE, buffer, bufferOffset, ExpResult.SHOULD_SUCCEED);
                bufferOffset = VerifyPrintResult("Generate key with invalid curve (fail is good):", SimpleECCApplet.ECTEST_GENERATE_KEYPAIR_INVALIDCUSTOMCURVE, buffer, bufferOffset, ExpResult.MUST_FAIL);
                if (buffer[bufferOffset] == SimpleECCApplet.ECTEST_DH_GENERATESECRET) {
                    bufferOffset = VerifyPrintResult("ECDH agreement with invalid point (fail is good):", SimpleECCApplet.ECTEST_DH_GENERATESECRET, buffer, bufferOffset, ExpResult.MUST_FAIL);
                }
                bufferOffset = VerifyPrintResult("Set valid custom curve:", SimpleECCApplet.ECTEST_SET_VALIDCURVE, buffer, bufferOffset, ExpResult.SHOULD_SUCCEED);
                bufferOffset = VerifyPrintResult("Generate key with valid curve:", SimpleECCApplet.ECTEST_GENERATE_KEYPAIR_CUSTOMCURVE, buffer, bufferOffset, ExpResult.SHOULD_SUCCEED);
            }

            systemOutLogger.println();
        }
    }

    private void PrintECKeyGenInvalidCurveB_lastUserParams(ResponseAPDU resp) {
        byte[] buffer = resp.getData();
        short offset = 0;
        systemOutLogger.print("Last used value of B: ");
        while (offset < buffer.length) {
            systemOutLogger.print(String.format("%x ", buffer[offset]));
            offset++;
        }
    }

    public static void main(String[] args) throws FileNotFoundException, IOException {
        SimpleAPDU app = new SimpleAPDU();
        app.run(args);
    }
}
