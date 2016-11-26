package simpleapdu;

import applets.EC_Consts;
import applets.SimpleECCApplet;
import javacard.framework.ISO7816;
import javacard.security.CryptoException;
import javacard.security.KeyPair;

import javax.smartcardio.ResponseAPDU;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;


/**
 * @author Petr Svenda petr@svenda.com
 */
public class SimpleAPDU {
    static CardMngr cardManager = new CardMngr();

    private final static byte SELECT_ECTESTERAPPLET[] = {(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0a,
            (byte) 0x45, (byte) 0x43, (byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x65, (byte) 0x72, (byte) 0x30, (byte) 0x31};

    static DirtyLogger m_SystemOutLogger = null;

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

    private static final byte TESTECSUPPORT_GENERATEECCKEY[] = {(byte) 0xB0, (byte) 0x5a, (byte) 0x00, (byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0x00};


    static short getShort(byte[] array, int offset) {
        return (short) (((array[offset] & 0xFF) << 8) | (array[offset + 1] & 0xFF));
    }

    static void setShort(byte[] array, int offset, short value) {
        array[offset + 1] = (byte) (value & 0xFF);
        array[offset] = (byte) ((value >> 8) & 0xFF);
    }

    static void testFPkeyGen_setNumRepeats(byte[] apduArray, short numRepeats) {
        setShort(apduArray, INVALIDCURVEB_NUMREPEATS_OFFSET, numRepeats);
    }

    static void testFPkeyGen_setCorruptionType(byte[] apduArray, short corruptionType) {
        setShort(apduArray, INVALIDCURVEB_CORRUPTIONTYPE_OFFSET, corruptionType);
    }

    static void testFPkeyGen_rewindOnSuccess(byte[] apduArray, boolean bRewind) {
        apduArray[INVALIDCURVEB_REWINDONSUCCESS_OFFSET] = bRewind ? (byte) 1 : (byte) 0;
    }

    static CardMngr ReconnnectToCard() throws Exception {
        cardManager.DisconnectFromCard();
        if (cardManager.ConnectToCard()) {
            // Select our application on card
            cardManager.sendAPDU(SELECT_ECTESTERAPPLET);
        }
        return cardManager;
    }

    static void testSupportECGivenAlg(byte[] apdu, CardMngr cardManager) throws Exception {
        ReconnnectToCard();
        ResponseAPDU resp = cardManager.sendAPDU(apdu);
        PrintECSupport(resp);
    }

    static void testSupportECAll(CardMngr cardManager) throws Exception {
        byte[] testAPDU = Arrays.copyOf(TESTECSUPPORT_GIVENALG, TESTECSUPPORT_GIVENALG.length);

        testAPDU[TESTECSUPPORT_ALG_OFFSET] = KeyPair.ALG_EC_FP;
        setShort(testAPDU, TESTECSUPPORT_KEYLENGTH_OFFSET, (short) 128);
        testSupportECGivenAlg(testAPDU, cardManager);
        setShort(testAPDU, TESTECSUPPORT_KEYLENGTH_OFFSET, (short) 160);
        testSupportECGivenAlg(testAPDU, cardManager);
        setShort(testAPDU, TESTECSUPPORT_KEYLENGTH_OFFSET, (short) 192);
        testSupportECGivenAlg(testAPDU, cardManager);
        setShort(testAPDU, TESTECSUPPORT_KEYLENGTH_OFFSET, (short) 224);
        testSupportECGivenAlg(testAPDU, cardManager);
        setShort(testAPDU, TESTECSUPPORT_KEYLENGTH_OFFSET, (short) 256);
        testSupportECGivenAlg(testAPDU, cardManager);
        setShort(testAPDU, TESTECSUPPORT_KEYLENGTH_OFFSET, (short) 384);
        testSupportECGivenAlg(testAPDU, cardManager);
        setShort(testAPDU, TESTECSUPPORT_KEYLENGTH_OFFSET, (short) 521);
        testSupportECGivenAlg(testAPDU, cardManager);

        testAPDU[TESTECSUPPORT_ALG_OFFSET] = KeyPair.ALG_EC_F2M;
        setShort(testAPDU, TESTECSUPPORT_KEYLENGTH_OFFSET, (short) 113);
        testSupportECGivenAlg(testAPDU, cardManager);
        setShort(testAPDU, TESTECSUPPORT_KEYLENGTH_OFFSET, (short) 131);
        testSupportECGivenAlg(testAPDU, cardManager);
        setShort(testAPDU, TESTECSUPPORT_KEYLENGTH_OFFSET, (short) 163);
        testSupportECGivenAlg(testAPDU, cardManager);
        setShort(testAPDU, TESTECSUPPORT_KEYLENGTH_OFFSET, (short) 193);
        testSupportECGivenAlg(testAPDU, cardManager);

    }


    public static void main(String[] args) throws FileNotFoundException, IOException {

        boolean genKeys = false;
        int genAmount = 0;
        boolean testAll = false;
        if (args.length > 0) {
            for (int i = 0; i < args.length; i++) {
                if (args[i].equals("-g")) {
                    genKeys = true;
                    if (args.length >= i + 1) {
                        try {
                            genAmount = Integer.parseInt(args[i + 1]);
                        }catch (NumberFormatException ignored) {
                            //is another param, genAmount = 0 by default
                            genAmount = 0;
                        }

                    }
                } else if (args[i].equals("-a")) {
                    testAll = true;
                }
            }
        }

        //by default do the test
        if (!genKeys && !testAll) {
            testAll = true;
        }


        String logFileName = String.format("ECTESTER_log_%d.log", System.currentTimeMillis());
        FileOutputStream systemOutLogger = new FileOutputStream(logFileName);
        m_SystemOutLogger = new DirtyLogger(systemOutLogger, true);

        try {
            if (testAll) {
                if (cardManager.ConnectToCard()) {
                    byte[] testAPDU2 = Arrays.copyOf(TESTECSUPPORT_GIVENALG, TESTECSUPPORT_GIVENALG.length);
                    testAPDU2[TESTECSUPPORT_ALG_OFFSET] = KeyPair.ALG_EC_FP;
                    setShort(testAPDU2, TESTECSUPPORT_KEYLENGTH_OFFSET, (short) 384);
                    testSupportECGivenAlg(testAPDU2, cardManager);

                    testSupportECAll(cardManager);
                    //
                    // Test setting invalid parameter B of curve
                    byte[] testAPDU = Arrays.copyOf(TESTECSUPPORTALL_FP_KEYGEN_INVALIDCURVEB, TESTECSUPPORTALL_FP_KEYGEN_INVALIDCURVEB.length);
                    //testFPkeyGen_setCorruptionType(testAPDU, SimpleECCApplet.CORRUPT_B_LASTBYTEINCREMENT);
                    testFPkeyGen_setCorruptionType(testAPDU, EC_Consts.CORRUPTION_ONEBYTERANDOM);
                    //testFPkeyGen_setCorruptionType(testAPDU, SimpleECCApplet.CORRUPT_B_FULLRANDOM);
                    testFPkeyGen_setNumRepeats(testAPDU, (short) 10);
                    testFPkeyGen_rewindOnSuccess(testAPDU, true);
                    ReconnnectToCard();
                    ResponseAPDU resp_fp_keygen = cardManager.sendAPDU(testAPDU);
                    ResponseAPDU resp_keygen_params = cardManager.sendAPDU(TESTECSUPPORTALL_LASTUSEDPARAMS);
                    PrintECKeyGenInvalidCurveB(resp_fp_keygen);
                    PrintECKeyGenInvalidCurveB_lastUserParams(resp_keygen_params);

                /*
                 // Test support for different types of curves
                 ReconnnectToCard();
                 ResponseAPDU resp_fp = cardManager.sendAPDU(TESTECSUPPORTALL_FP);
                 ReconnnectToCard();
                 ResponseAPDU resp_f2m = cardManager.sendAPDU(TESTECSUPPORTALL_F2M);
                 PrintECSupport(resp_fp);
                 PrintECSupport(resp_f2m);
                 */

                    cardManager.DisconnectFromCard();
                } else {
                    m_SystemOutLogger.println("Failed to connect to card");
                }
            }

            if (genKeys) {
                // Gather large number of ECC keypairs
                if (cardManager.ConnectToCardSelect()) {
                    cardManager.sendAPDU(SELECT_ECTESTERAPPLET);

                    String keyFileName = String.format("ECKEYS_%d.log", System.currentTimeMillis());
                    FileOutputStream keysFile = new FileOutputStream(keyFileName);

                    String message = "index;time;pubW;privS\n";
                    keysFile.write(message.getBytes());
                    byte[] gatherKeyAPDU = Arrays.copyOf(TESTECSUPPORT_GENERATEECCKEY, TESTECSUPPORT_GENERATEECCKEY.length);
                    // Prepare keypair object
                    gatherKeyAPDU[ISO7816.OFFSET_P1] = SimpleECCApplet.P1_SETCURVE;
                    setShort(gatherKeyAPDU, (short) 5, (short) 192);    // ecc length
                    ResponseAPDU respGather = cardManager.sendAPDU(gatherKeyAPDU);

                    // Generate new keypair
                    gatherKeyAPDU[ISO7816.OFFSET_P1] = SimpleECCApplet.P1_GENERATEKEYPAIR;
                    int counter = 0;
                    while (true) {
                        counter++;
                        long elapsed = -System.nanoTime();
                        respGather = cardManager.sendAPDU(gatherKeyAPDU);
                        elapsed += System.nanoTime();

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

                        m_SystemOutLogger.flush();
                        keysFile.flush();

                        //stop when we have enough keys, go on forever with 0
                        if (counter >= genAmount && genAmount != 0)
                            break;
                    }
                }
            }


        } catch (Exception ex) {
            m_SystemOutLogger.println("Exception : " + ex);
        }

        systemOutLogger.close();
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
            if (code == SimpleECCApplet.SW_SIG_LENGTH_MISMATCH) {
                codeStr = "SW_SIG_LENGTH_MISMATCH";
            }
            if (code == SimpleECCApplet.SW_SIG_VERIFY_FAIL) {
                codeStr = "SW_SIG_VERIFY_FAIL";
            }
            return String.format("fail\t(%s,\t0x%4x)", codeStr, code);
        }
    }

    enum ExpResult {
        SHOULD_SUCCEDD,
        MAY_FAIL,
        MUST_FAIL
    }

    static int VerifyPrintResult(String message, byte expectedTag, byte[] buffer, int bufferOffset, ExpResult expRes) {
        if (bufferOffset >= buffer.length) {
            m_SystemOutLogger.println("   No more data returned");
        } else {
            if (buffer[bufferOffset] != expectedTag) {
                m_SystemOutLogger.println("   ERROR: mismatched tag");
                assert (buffer[bufferOffset] == expectedTag);
            }
            bufferOffset++;
            short resCode = getShort(buffer, bufferOffset);
            bufferOffset += 2;

            boolean bHiglight = false;
            if ((expRes == ExpResult.MUST_FAIL) && (resCode == ISO7816.SW_NO_ERROR)) {
                bHiglight = true;
            }
            if ((expRes == ExpResult.SHOULD_SUCCEDD) && (resCode != ISO7816.SW_NO_ERROR)) {
                bHiglight = true;
            }
            if (bHiglight) {
                m_SystemOutLogger.println(String.format("!! %-50s%s", message, getPrintError(resCode)));
            } else {
                m_SystemOutLogger.println(String.format("   %-50s%s", message, getPrintError(resCode)));
            }
        }
        return bufferOffset;
    }

    static void PrintECSupport(ResponseAPDU resp) {
        byte[] buffer = resp.getData();

        m_SystemOutLogger.println();
        m_SystemOutLogger.println("### Test for support and with valid and invalid EC curves");
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
            m_SystemOutLogger.println(String.format("%-53s%s", "EC type:", ecType));
            bufferOffset++;
            short keyLen = getShort(buffer, bufferOffset);
            m_SystemOutLogger.println(String.format("%-53s%d bits", "EC key length (bits):", keyLen));
            bufferOffset += 2;

            bufferOffset = VerifyPrintResult("KeyPair object allocation:", SimpleECCApplet.ECTEST_ALLOCATE_KEYPAIR, buffer, bufferOffset, ExpResult.SHOULD_SUCCEDD);
            bufferOffset = VerifyPrintResult("Generate key with def curve (fails if no def):", SimpleECCApplet.ECTEST_GENERATE_KEYPAIR_DEFCURVE, buffer, bufferOffset, ExpResult.MAY_FAIL);
            bufferOffset = VerifyPrintResult("Set valid custom curve:", SimpleECCApplet.ECTEST_SET_VALIDCURVE, buffer, bufferOffset, ExpResult.SHOULD_SUCCEDD);
            bufferOffset = VerifyPrintResult("Generate key with valid curve:", SimpleECCApplet.ECTEST_GENERATE_KEYPAIR_CUSTOMCURVE, buffer, bufferOffset, ExpResult.SHOULD_SUCCEDD);
            bufferOffset = VerifyPrintResult("ECDH agreement with valid point:", SimpleECCApplet.ECTEST_ECDH_AGREEMENT_VALID_POINT, buffer, bufferOffset, ExpResult.SHOULD_SUCCEDD);
            bufferOffset = VerifyPrintResult("ECDH agreement with invalid point (fail is good):", SimpleECCApplet.ECTEST_ECDH_AGREEMENT_INVALID_POINT, buffer, bufferOffset, ExpResult.MUST_FAIL);
            bufferOffset = VerifyPrintResult("Set invalid custom curve (may fail):", SimpleECCApplet.ECTEST_SET_INVALIDCURVE, buffer, bufferOffset, ExpResult.MAY_FAIL);
            bufferOffset = VerifyPrintResult("Generate key with invalid curve (fail is good):", SimpleECCApplet.ECTEST_GENERATE_KEYPAIR_INVALIDCUSTOMCURVE, buffer, bufferOffset, ExpResult.MUST_FAIL);

            m_SystemOutLogger.println();
        }
    }

    static void PrintECKeyGenInvalidCurveB(ResponseAPDU resp) {
        byte[] buffer = resp.getData();

        m_SystemOutLogger.println();
        m_SystemOutLogger.println("### Test for computation with invalid parameter B for EC curve");
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
            m_SystemOutLogger.println(String.format("%-53s%s", "EC type:", ecType));
            bufferOffset++;
            short keyLen = getShort(buffer, bufferOffset);
            m_SystemOutLogger.println(String.format("%-53s%d bits", "EC key length (bits):", keyLen));
            bufferOffset += 2;

            short numRepeats = getShort(buffer, bufferOffset);
            bufferOffset += 2;
            m_SystemOutLogger.println(String.format("%-53s%d times", "Executed repeats before unexpected error: ", numRepeats));

            bufferOffset = VerifyPrintResult("KeyPair object allocation:", SimpleECCApplet.ECTEST_ALLOCATE_KEYPAIR, buffer, bufferOffset, ExpResult.SHOULD_SUCCEDD);
            while (bufferOffset < buffer.length) {
                bufferOffset = VerifyPrintResult("Set invalid custom curve:", SimpleECCApplet.ECTEST_SET_INVALIDCURVE, buffer, bufferOffset, ExpResult.SHOULD_SUCCEDD);
                bufferOffset = VerifyPrintResult("Generate key with invalid curve (fail is good):", SimpleECCApplet.ECTEST_GENERATE_KEYPAIR_INVALIDCUSTOMCURVE, buffer, bufferOffset, ExpResult.MUST_FAIL);
                if (buffer[bufferOffset] == SimpleECCApplet.ECTEST_DH_GENERATESECRET) {
                    bufferOffset = VerifyPrintResult("ECDH agreement with invalid point (fail is good):", SimpleECCApplet.ECTEST_DH_GENERATESECRET, buffer, bufferOffset, ExpResult.MUST_FAIL);
                }
                bufferOffset = VerifyPrintResult("Set valid custom curve:", SimpleECCApplet.ECTEST_SET_VALIDCURVE, buffer, bufferOffset, ExpResult.SHOULD_SUCCEDD);
                bufferOffset = VerifyPrintResult("Generate key with valid curve:", SimpleECCApplet.ECTEST_GENERATE_KEYPAIR_CUSTOMCURVE, buffer, bufferOffset, ExpResult.SHOULD_SUCCEDD);
            }

            m_SystemOutLogger.println();
        }
    }

    static void PrintECKeyGenInvalidCurveB_lastUserParams(ResponseAPDU resp) {
        byte[] buffer = resp.getData();
        short offset = 0;
        m_SystemOutLogger.print("Last used value of B: ");
        while (offset < buffer.length) {
            m_SystemOutLogger.print(String.format("%x ", buffer[offset]));
            offset++;
        }

    }
}
