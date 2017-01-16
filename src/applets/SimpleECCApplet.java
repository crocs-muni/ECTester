/*
 * PACKAGEID: 4C6162616B417070
 * APPLETID: 4C6162616B4170706C6574
 */
package applets;

import javacard.framework.*;
import javacard.security.*;


public class SimpleECCApplet extends Applet {

    // MAIN INSTRUCTION CLASS
    final static byte CLA_SIMPLEECCAPPLET = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_GENERATEKEY = (byte) 0x5a;
    final static byte INS_ALLOCATEKEYPAIRS = (byte) 0x5b;

    final static byte INS_ALLOCATEKEYPAIR = (byte) 0x5c;
    final static byte INS_DERIVEECDHSECRET = (byte) 0x5d;

    final static byte INS_TESTECSUPPORTALL_FP = (byte) 0x5e;
    final static byte INS_TESTECSUPPORTALL_F2M = (byte) 0x5f;
    final static byte INS_TESTEC_GENERATEINVALID_FP = (byte) 0x70;
    final static byte INS_TESTECSUPPORT_GIVENALG = (byte) 0x71;
    final static byte INS_TESTECSUPPORT_EXTERNAL = (byte) 0x72;
    final static byte INS_TESTEC_LASTUSEDPARAMS = (byte) 0x40;


    public final static byte P1_SETCURVE = (byte) 0x01;
    public final static byte P1_GENERATEKEYPAIR = (byte) 0x02;


    final static short ARRAY_LENGTH = (short) 0xff;
    final static byte AES_BLOCK_LENGTH = (short) 0x16;

    final static short EC_LENGTH_BITS = KeyBuilder.LENGTH_EC_FP_192;
    //final static short EC_LENGTH_BITS = KeyBuilder.LENGTH_EC_FP_160;
    //final static short EC_LENGTH_BITS = (short) 256;

    public final static byte ECTEST_SEPARATOR = (byte) 0xff;
    public final static byte ECTEST_ALLOCATE_KEYPAIR = (byte) 0xc1;
    public final static byte ECTEST_GENERATE_KEYPAIR_DEFCURVE = (byte) 0xc2;
    public final static byte ECTEST_SET_VALIDCURVE = (byte) 0xc3;
    public final static byte ECTEST_GENERATE_KEYPAIR_CUSTOMCURVE = (byte) 0xc4;
    public final static byte ECTEST_SET_INVALIDCURVE = (byte) 0xc5;
    public final static byte ECTEST_GENERATE_KEYPAIR_INVALIDCUSTOMCURVE = (byte) 0xc6;
    public final static byte ECTEST_ECDH_AGREEMENT_VALID_POINT = (byte) 0xc7;
    public final static byte ECTEST_ECDH_AGREEMENT_INVALID_POINT = (byte) 0xc8;
    public final static byte ECTEST_EXECUTED_REPEATS = (byte) 0xc9;
    public final static byte ECTEST_DH_GENERATESECRET = (byte) 0xca;
    public final static byte ECTEST_SET_EXTERNALCURVE = (byte) 0xcb;
    public final static byte ECTEST_GENERATE_KEYPAIR_EXTERNALCURVE = (byte) 0xcc;
    public final static byte ECTEST_ECDSA_SIGNATURE = (byte) 0xcd;
    public final static byte ECTEST_SET_ANOMALOUSCURVE = (byte) 0xce;
    public final static byte ECTEST_GENERATE_KEYPAIR_ANOMALOUSCURVE = (byte) 0xcf;
    public final static byte ECTEST_ECDH_AGREEMENT_SMALL_DEGREE_POINT = (byte) 0xd0;
    public final static byte ECTEST_SET_INVALIDFIELD = (byte) 0xd1;
    public final static byte ECTEST_GENERATE_KEYPAIR_INVALIDFIELD = (byte) 0xd2;

    public final static short FLAG_ECTEST_ALLOCATE_KEYPAIR = (short) 0x0001;
    public final static short FLAG_ECTEST_GENERATE_KEYPAIR_DEFCURVE = (short) 0x0002;
    public final static short FLAG_ECTEST_SET_VALIDCURVE = (short) 0x0004;
    public final static short FLAG_ECTEST_GENERATE_KEYPAIR_CUSTOMCURVE = (short) 0x0008;
    public final static short FLAG_ECTEST_SET_INVALIDCURVE = (short) 0x0010;
    public final static short FLAG_ECTEST_GENERATE_KEYPAIR_INVALIDCUSTOMCURVE = (short) 0x0020;
    public final static short FLAG_ECTEST_ECDH_AGREEMENT_VALID_POINT = (short) 0x0040;
    public final static short FLAG_ECTEST_ECDH_AGREEMENT_INVALID_POINT = (short) 0x0080;
    public final static short FLAG_ECTEST_ECDSA_SIGNATURE = (short) 0x0100;
    public final static short FLAG_ECTEST_SET_ANOMALOUSCURVE = (short) 0x0200;
    public final static short FLAG_ECTEST_GENERATE_KEYPAIR_ANOMALOUSCUVE = (short) 0x0400;
    public final static short FLAG_ECTEST_ECDH_AGREEMENT_SMALL_DEGREE_POINT = (short) 0x0800;
    public final static short FLAG_ECTEST_SET_INVALIDFIELD = (short) 0x1000;
    public final static short FLAG_ECTEST_GENERATE_KEYPAIR_INVALIDFIELD = (short) 0x2000;

    public final static short FLAG_ECTEST_ALL = (short) 0xffff;


    public final static short SW_SKIPPED = (short) 0x0ee1;
    public final static short SW_KEYPAIR_GENERATED_INVALID = (short) 0x0ee2;
    public final static short SW_INVALID_CORRUPTION_TYPE = (short) 0x0ee3;
    public final static short SW_SIG_VERIFY_FAIL = (short) 0xee4;
    /*
        public static final byte[] EC192_FP_PUBLICW = new byte[]{
            (byte) 0x04, (byte) 0xC9, (byte) 0xC0, (byte) 0xED, (byte) 0xFB, (byte) 0x27,
            (byte) 0xB7, (byte) 0x1E, (byte) 0xBE, (byte) 0x30, (byte) 0x93, (byte) 0xFC,
            (byte) 0x4F, (byte) 0x33, (byte) 0x76, (byte) 0x38, (byte) 0xCE, (byte) 0xE0,
            (byte) 0x2F, (byte) 0x78, (byte) 0xF6, (byte) 0x3C, (byte) 0xEA, (byte) 0x90,
            (byte) 0x22, (byte) 0x61, (byte) 0x32, (byte) 0x8E, (byte) 0x9F, (byte) 0x03,
            (byte) 0x8A, (byte) 0xFD, (byte) 0x60, (byte) 0xA0, (byte) 0xCE, (byte) 0x01,
            (byte) 0x9B, (byte) 0x76, (byte) 0x34, (byte) 0x59, (byte) 0x79, (byte) 0x64,
            (byte) 0xD7, (byte) 0x79, (byte) 0x8E, (byte) 0x3B, (byte) 0x16, (byte) 0xD5,
            (byte) 0x15};
        */
    public static final byte[] EC192_FP_PUBLICW = new byte[]{
            (byte) 0x04,
            (byte) 0x9d, (byte) 0x42, (byte) 0x76, (byte) 0x9d, (byte) 0xfd, (byte) 0xbe,
            (byte) 0x11, (byte) 0x3a, (byte) 0x85, (byte) 0x1b, (byte) 0xb6, (byte) 0xb0,
            (byte) 0x1b, (byte) 0x1a, (byte) 0x51, (byte) 0x5d, (byte) 0x89, (byte) 0x3b,
            (byte) 0x5a, (byte) 0xdb, (byte) 0xc1, (byte) 0xf6, (byte) 0x13, (byte) 0x29,
            (byte) 0x74, (byte) 0x74, (byte) 0x9a, (byte) 0xc0, (byte) 0x96, (byte) 0x7a,
            (byte) 0x8f, (byte) 0xf4, (byte) 0xcc, (byte) 0x54, (byte) 0xd9, (byte) 0x31,
            (byte) 0x87, (byte) 0x60, (byte) 0x2d, (byte) 0xd6, (byte) 0x7e, (byte) 0xb3,
            (byte) 0xd2, (byte) 0x29, (byte) 0x70a, (byte) 0xca, (byte) 0x2ca};


    private ECPublicKey ecPubKey = null;
    private ECPublicKey ecPubKey128 = null;
    private ECPublicKey ecPubKey160 = null;
    private ECPublicKey ecPubKey192 = null;
    private ECPublicKey ecPubKey256 = null;
    private ECPrivateKey ecPrivKey = null;
    private ECPrivateKey ecPrivKey128 = null;
    private ECPrivateKey ecPrivKey160 = null;
    private ECPrivateKey ecPrivKey192 = null;
    private ECPrivateKey ecPrivKey256 = null;

    private ECKeyGenerator ecKeyGenerator = null;
    private ECKeyTester ecKeyTester = null;

    private KeyAgreement dhKeyAgreement = null;
    private RandomData randomData = null;

    // TEMPORARRY ARRAY IN RAM
    private byte m_ramArray[] = null;
    private byte m_ramArray2[] = null;
    // PERSISTENT ARRAY IN EEPROM
    private byte m_dataArray[] = null;

    short m_lenB = 0;

    protected SimpleECCApplet(byte[] buffer, short offset, byte length) {
        short dataOffset = offset;

        if (length > 9) {
            // shift to privilege offset
            dataOffset += (short) (1 + buffer[offset]);
            // finally shift to Application specific offset
            dataOffset += (short) (1 + buffer[dataOffset]);
            // go to proprietary data
            dataOffset++;

            m_ramArray = JCSystem.makeTransientByteArray(ARRAY_LENGTH, JCSystem.CLEAR_ON_RESET);
            m_ramArray2 = JCSystem.makeTransientByteArray(ARRAY_LENGTH, JCSystem.CLEAR_ON_RESET);

            m_dataArray = new byte[ARRAY_LENGTH];
            Util.arrayFillNonAtomic(m_dataArray, (short) 0, ARRAY_LENGTH, (byte) 0);

            randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
            EC_Consts.m_random = randomData;

            ecKeyGenerator = new ECKeyGenerator();
            ecKeyTester = new ECKeyTester();
            ecKeyTester.allocateECDH();
            ecKeyTester.allocateECDHC();
            ecKeyTester.allocateECDSA();

        }

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        // applet  instance creation 
        new SimpleECCApplet(bArray, bOffset, bLength);
    }

    public boolean select() {
        return true;
    }

    public void deselect() {
        return;
    }

    public void process(APDU apdu) throws ISOException {
        // get the APDU buffer
        byte[] apduBuffer = apdu.getBuffer();

        // ignore the applet select command dispached to the process
        if (selectingApplet())
            return;

        if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_SIMPLEECCAPPLET) {
            switch (apduBuffer[ISO7816.OFFSET_INS]) {

                case INS_TESTECSUPPORT_GIVENALG:
                    TestEC_SupportGivenLength(apdu);
                    break;
                case INS_TESTECSUPPORTALL_FP:
                    TestEC_FP_SupportAllLengths(apdu);
                    break;
                case INS_TESTECSUPPORTALL_F2M:
                    TestEC_F2M_SupportAllLengths(apdu);
                    break;
                case INS_ALLOCATEKEYPAIR:
                    AllocateKeyPairReturnDefCurve(apdu);
                    break;
                case INS_DERIVEECDHSECRET:
                    DeriveECDHSecret(apdu);
                    break;
                case INS_TESTEC_GENERATEINVALID_FP:
                    TestEC_FP_GenerateInvalidCurve(apdu);
                    break;
                case INS_TESTEC_LASTUSEDPARAMS:
                    TestECSupportInvalidCurve_lastUsedParams(apdu);
                    break;
                case INS_TESTECSUPPORT_EXTERNAL:
                    TestEC_SupportExternal(apdu);
                    break;
/*                    
                case INS_ALLOCATEKEYPAIRS:
                    AllocateKeyPairs(apdu);
                    break;
*/
                case INS_GENERATEKEY:
                    GenerateAndReturnKey(apdu);
                    break;
                default:
                    // The INS code is not supported by the dispatcher
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                    break;

            }
        } else ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }


    short TestECSupport(byte keyClass, short keyLen, byte[] buffer, short bufferOffset) {
        short baseOffset = bufferOffset;

        short testFlags = FLAG_ECTEST_ALL;

        ecPubKey = null;
        ecPrivKey = null;

        buffer[bufferOffset] = ECTEST_SEPARATOR;
        bufferOffset++;
        buffer[bufferOffset] = keyClass;
        bufferOffset++;
        Util.setShort(buffer, bufferOffset, keyLen);
        bufferOffset += 2;

        short sw;

        //
        // 1. Allocate KeyPair object
        //
        buffer[bufferOffset] = ECTEST_ALLOCATE_KEYPAIR;
        bufferOffset++;
        sw = SW_SKIPPED;
        if ((testFlags & FLAG_ECTEST_ALLOCATE_KEYPAIR) != (short) 0) {
            sw = ecKeyGenerator.allocatePair(keyClass, keyLen);

            if (sw != ISO7816.SW_NO_ERROR) {
                testFlags = 0; //keyPair allocation failed, cannot continue with tests
            }
        }
        Util.setShort(buffer, bufferOffset, sw);
        bufferOffset += 2;

        //
        // 2. Test keypair generation without explicit curve (=> default curve preset)    
        //
        buffer[bufferOffset] = ECTEST_GENERATE_KEYPAIR_DEFCURVE;
        bufferOffset++;
        sw = SW_SKIPPED;
        if ((testFlags & FLAG_ECTEST_GENERATE_KEYPAIR_DEFCURVE) != (short) 0) {
            sw = ecKeyGenerator.generatePair();
        }
        Util.setShort(buffer, bufferOffset, sw);
        bufferOffset += 2;

        //
        // 3. Set valid custom curve
        //
        buffer[bufferOffset] = ECTEST_SET_VALIDCURVE;
        bufferOffset++;
        sw = SW_SKIPPED;
        if ((testFlags & FLAG_ECTEST_SET_VALIDCURVE) != (short) 0) {
            sw = ecKeyGenerator.setCustomCurve(keyClass, keyLen, m_ramArray, (short) 0);

            if (sw != ISO7816.SW_NO_ERROR) {
                testFlags &= ~FLAG_ECTEST_GENERATE_KEYPAIR_CUSTOMCURVE;
            }
        }
        Util.setShort(buffer, bufferOffset, sw);
        bufferOffset += 2;

        //
        // 4. Generate keypair with custom curve       
        //
        buffer[bufferOffset] = ECTEST_GENERATE_KEYPAIR_CUSTOMCURVE;
        bufferOffset++;
        sw = SW_SKIPPED;
        if ((testFlags & FLAG_ECTEST_GENERATE_KEYPAIR_CUSTOMCURVE) != (short) 0) {
            sw = ecKeyGenerator.generatePair();
        }
        Util.setShort(buffer, bufferOffset, sw);
        bufferOffset += 2;

        //
        // 5. ECDH agreement with valid public key
        //
        buffer[bufferOffset] = ECTEST_ECDH_AGREEMENT_VALID_POINT;
        bufferOffset++;
        sw = SW_SKIPPED;
        if ((testFlags & FLAG_ECTEST_ECDH_AGREEMENT_VALID_POINT) != (short) 0) {
            sw = ecKeyGenerator.generatePair();
            if (sw == ISO7816.SW_NO_ERROR) {
                ecPubKey = ecKeyGenerator.getPublicKey();
                ecPrivKey = ecKeyGenerator.getPrivateKey();
                sw = ecKeyTester.testECDH_validPoint(ecPrivKey, ecPubKey, m_ramArray, (short) 0, m_ramArray2, (short) 0);
            }
        }
        Util.setShort(buffer, bufferOffset, sw);
        bufferOffset += 2;

        //
        // 6. ECDH agreement with invalid public key
        //
        buffer[bufferOffset] = ECTEST_ECDH_AGREEMENT_INVALID_POINT;
        bufferOffset++;
        sw = SW_SKIPPED;
        if ((testFlags & FLAG_ECTEST_ECDH_AGREEMENT_INVALID_POINT) != (short) 0) {
            sw = ecKeyGenerator.generatePair();
            if (sw == ISO7816.SW_NO_ERROR) {
                ecPubKey = ecKeyGenerator.getPublicKey();
                ecPrivKey = ecKeyGenerator.getPrivateKey();
                sw = ecKeyTester.testECDH_invalidPoint(ecPrivKey, ecPubKey, m_ramArray, (short) 0, m_ramArray2, (short) 1);
            }
        }
        Util.setShort(buffer, bufferOffset, sw);
        bufferOffset += 2;

        //
        // 7. ECDSA test
        //
        buffer[bufferOffset] = ECTEST_ECDSA_SIGNATURE;
        bufferOffset++;
        sw = SW_SKIPPED;
        if ((testFlags & FLAG_ECTEST_ECDSA_SIGNATURE) != (short) 0) {
            sw = ecKeyGenerator.generatePair();
            if (sw == ISO7816.SW_NO_ERROR) {
                ecPubKey = ecKeyGenerator.getPublicKey();
                ecPrivKey = ecKeyGenerator.getPrivateKey();
                sw = ecKeyTester.testECDSA(ecPrivKey, ecPubKey, m_ramArray2, (short) 0, (short) m_ramArray2.length, m_ramArray, (short) 0);
            }
        }
        Util.setShort(buffer, bufferOffset, sw);
        bufferOffset += 2;

        //
        // 8. Set anomalous custom curve
        //
        buffer[bufferOffset] = ECTEST_SET_ANOMALOUSCURVE;
        bufferOffset++;
        sw = SW_SKIPPED;
        if ((testFlags & FLAG_ECTEST_SET_ANOMALOUSCURVE) != (short) 0) {
            if (keyClass == KeyPair.ALG_EC_FP) { //Only FP supported at the moment
                sw = ecKeyGenerator.setCustomAnomalousCurve(keyClass, keyLen, m_ramArray, (short) 0);
            }
            if (sw != ISO7816.SW_NO_ERROR) {
                testFlags &= ~FLAG_ECTEST_GENERATE_KEYPAIR_ANOMALOUSCUVE;
                testFlags &= ~FLAG_ECTEST_ECDH_AGREEMENT_SMALL_DEGREE_POINT;
            }
        }
        Util.setShort(buffer, bufferOffset, sw);
        bufferOffset += 2;

        //
        // 9. Generate keypair with anomalous custom curve
        //

        buffer[bufferOffset] = ECTEST_GENERATE_KEYPAIR_ANOMALOUSCURVE;
        bufferOffset++;
        sw = SW_SKIPPED;
        if ((testFlags & FLAG_ECTEST_GENERATE_KEYPAIR_ANOMALOUSCUVE) != (short) 0) {
            sw = ecKeyGenerator.generatePair();
            if (sw != ISO7816.SW_NO_ERROR) {
                testFlags &= ~FLAG_ECTEST_ECDH_AGREEMENT_SMALL_DEGREE_POINT;
            }
        }
        Util.setShort(buffer, bufferOffset, sw);
        bufferOffset += 2;

        //
        // 10. Test small degree pubkey
        //

        buffer[bufferOffset] = ECTEST_ECDH_AGREEMENT_SMALL_DEGREE_POINT;
        bufferOffset++;
        sw = SW_SKIPPED;
        if ((testFlags & FLAG_ECTEST_ECDH_AGREEMENT_SMALL_DEGREE_POINT) != (short) 0) {
            short pubLength = EC_Consts.getCurveParameter(EC_Consts.getAnomalousCurve(keyClass, keyLen), EC_Consts.PARAMETER_W, m_ramArray, (short) 0);
            ecPrivKey = ecKeyGenerator.getPrivateKey();
            sw = ecKeyTester.testECDH(ecPrivKey, m_ramArray, (short) 0, pubLength, m_ramArray2, (short) 1);
        }
        Util.setShort(buffer, bufferOffset, sw);
        bufferOffset += 2;

        //
        // 11. Set invalid custom curve
        //
        buffer[bufferOffset] = ECTEST_SET_INVALIDCURVE;
        bufferOffset++;
        sw = SW_SKIPPED;
        if ((testFlags & FLAG_ECTEST_SET_INVALIDCURVE) != (short) 0) {
            sw = ecKeyGenerator.setCustomInvalidCurve(keyClass, keyLen, ECKeyGenerator.KEY_PUBLIC, EC_Consts.PARAMETER_B, EC_Consts.CORRUPTION_FIXED, m_ramArray, (short) 0);

            if (sw != ISO7816.SW_NO_ERROR) {
                testFlags &= ~FLAG_ECTEST_GENERATE_KEYPAIR_INVALIDCUSTOMCURVE;
            }
        }
        Util.setShort(buffer, bufferOffset, sw);
        bufferOffset += 2;

        //
        // 12. Generate keypair with invalid custom curve
        //
        buffer[bufferOffset] = ECTEST_GENERATE_KEYPAIR_INVALIDCUSTOMCURVE;
        bufferOffset++;
        sw = SW_SKIPPED;
        if ((testFlags & FLAG_ECTEST_GENERATE_KEYPAIR_INVALIDCUSTOMCURVE) != (short) 0) {
            sw = ecKeyGenerator.generatePair();
        }
        Util.setShort(buffer, bufferOffset, sw);
        bufferOffset += 2;

        //
        // 13. Set invalid field
        //
        buffer[bufferOffset] = ECTEST_SET_INVALIDFIELD;
        bufferOffset++;
        sw = SW_SKIPPED;
        if ((testFlags & FLAG_ECTEST_SET_INVALIDFIELD) != (short) 0) {
            if (keyClass == KeyPair.ALG_EC_FP)
                sw = ecKeyGenerator.setCustomInvalidCurve(keyClass, keyLen, ECKeyGenerator.KEY_BOTH, EC_Consts.PARAMETER_FP, EC_Consts.CORRUPTION_FULLRANDOM, m_ramArray, (short) 0);
            else
                sw = ecKeyGenerator.setCustomInvalidCurve(keyClass, keyLen, ECKeyGenerator.KEY_BOTH, EC_Consts.PARAMETER_F2M, EC_Consts.CORRUPTION_FULLRANDOM, m_ramArray, (short) 0);

            if (sw != ISO7816.SW_NO_ERROR) {
                testFlags &= ~FLAG_ECTEST_GENERATE_KEYPAIR_INVALIDFIELD;
            }
        }
        Util.setShort(buffer, bufferOffset, sw);
        bufferOffset += 2;

        // 14. Generate key with invalid field
        buffer[bufferOffset] = ECTEST_GENERATE_KEYPAIR_INVALIDFIELD;
        bufferOffset++;
        sw = SW_SKIPPED;
        if ((testFlags & FLAG_ECTEST_GENERATE_KEYPAIR_INVALIDFIELD) != (short) 0) {
            sw = ecKeyGenerator.generatePair();
        }
        Util.setShort(buffer, bufferOffset, sw);
        bufferOffset += 2;

        return (short) (bufferOffset - baseOffset);
    }

    void TestEC_SupportGivenLength(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        short dataOffset = ISO7816.OFFSET_CDATA;
        byte algType = apdubuf[dataOffset];
        dataOffset++;
        short keyLength = Util.getShort(apdubuf, dataOffset);
        dataOffset += 2;

        dataOffset = 0;
        dataOffset += TestECSupport(algType, keyLength, apdubuf, dataOffset);

        apdu.setOutgoingAndSend((short) 0, dataOffset);
    }

    void TestEC_FP_SupportAllLengths(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        short dataOffset = 0;

        // FP  
        dataOffset += TestECSupport(KeyPair.ALG_EC_FP, (short) 128, apdubuf, dataOffset);
        dataOffset += TestECSupport(KeyPair.ALG_EC_FP, (short) 160, apdubuf, dataOffset);
        dataOffset += TestECSupport(KeyPair.ALG_EC_FP, (short) 192, apdubuf, dataOffset);
        dataOffset += TestECSupport(KeyPair.ALG_EC_FP, (short) 224, apdubuf, dataOffset);
        dataOffset += TestECSupport(KeyPair.ALG_EC_FP, (short) 256, apdubuf, dataOffset);
        dataOffset += TestECSupport(KeyPair.ALG_EC_FP, (short) 384, apdubuf, dataOffset);
        dataOffset += TestECSupport(KeyPair.ALG_EC_FP, (short) 521, apdubuf, dataOffset);

        apdu.setOutgoingAndSend((short) 0, dataOffset);
    }

    void TestEC_F2M_SupportAllLengths(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        short dataOffset = 0;
        // F2M
        dataOffset += TestECSupport(KeyPair.ALG_EC_F2M, (short) 113, apdubuf, dataOffset);
        dataOffset += TestECSupport(KeyPair.ALG_EC_F2M, (short) 131, apdubuf, dataOffset);
        dataOffset += TestECSupport(KeyPair.ALG_EC_F2M, (short) 163, apdubuf, dataOffset);
        dataOffset += TestECSupport(KeyPair.ALG_EC_F2M, (short) 193, apdubuf, dataOffset);

        apdu.setOutgoingAndSend((short) 0, dataOffset);
    }

    short TestECSupportExternalCurve(byte keyClass, short keyLength, byte[] buffer, short bufferOffset, short outputOffset) {
        short startOffset = outputOffset;

        short fieldLength = Util.getShort(buffer, bufferOffset);
        bufferOffset += 2;
        short aLength = Util.getShort(buffer, bufferOffset);
        bufferOffset += 2;
        short bLength = Util.getShort(buffer, bufferOffset);
        bufferOffset += 2;
        short gxLength = Util.getShort(buffer, bufferOffset);
        bufferOffset += 2;
        short gyLength = Util.getShort(buffer, bufferOffset);
        bufferOffset += 2;
        short rLength = Util.getShort(buffer, bufferOffset);
        bufferOffset += 2;

        buffer[outputOffset] = ECTEST_SEPARATOR;
        outputOffset++;

        // allocatePair
        buffer[outputOffset] = ECTEST_ALLOCATE_KEYPAIR;
        outputOffset++;
        short sw = ecKeyGenerator.allocatePair(keyClass, keyLength);
        Util.setShort(buffer, outputOffset, sw);
        outputOffset += 2;
        if (sw != ISO7816.SW_NO_ERROR) {
            return (short) (outputOffset - startOffset);
        }

        // setExternalCurve
        buffer[outputOffset] = ECTEST_SET_EXTERNALCURVE;
        outputOffset++;
        sw = ecKeyGenerator.setExternalCurve(ECKeyGenerator.KEY_BOTH, keyClass, buffer, bufferOffset, fieldLength, aLength, bLength, gxLength, gyLength, rLength);
        Util.setShort(buffer, outputOffset, sw);
        outputOffset += 2;
        if (sw != ISO7816.SW_NO_ERROR) {
            return (short) (outputOffset - startOffset);
        }

        // generatePair
        buffer[outputOffset] = ECTEST_GENERATE_KEYPAIR_EXTERNALCURVE;
        outputOffset++;
        sw = ecKeyGenerator.generatePair();
        Util.setShort(buffer, outputOffset, sw);
        outputOffset += 2;
        if (sw != ISO7816.SW_NO_ERROR) {
            return (short) (outputOffset - startOffset);
        }

        ecPubKey = ecKeyGenerator.getPublicKey();
        ecPrivKey = ecKeyGenerator.getPrivateKey();

        // test_ECDH
        buffer[outputOffset] = ECTEST_ECDH_AGREEMENT_VALID_POINT;
        outputOffset++;
        sw = ecKeyTester.testECDH_validPoint(ecPrivKey, ecPubKey, m_ramArray, (short) 0, m_ramArray2, (short) 0);
        Util.setShort(buffer, outputOffset, sw);
        outputOffset += 2;
        if (sw != ISO7816.SW_NO_ERROR) {
            return (short) (outputOffset - startOffset);
        }

        // test_ECDH invalid
        buffer[outputOffset] = ECTEST_ECDH_AGREEMENT_INVALID_POINT;
        outputOffset++;
        sw = ecKeyTester.testECDH_invalidPoint(ecPrivKey, ecPubKey, m_ramArray, (short) 0, m_ramArray2, (short) 0);
        Util.setShort(buffer, outputOffset, sw);
        outputOffset += 2;
        if (sw != ISO7816.SW_NO_ERROR) {
            return (short) (outputOffset - startOffset);
        }

        // test_ECDSA
        buffer[outputOffset] = ECTEST_ECDSA_SIGNATURE;
        outputOffset++;
        randomData.generateData(m_ramArray, (short) 0, (short) (ARRAY_LENGTH / 2));
        sw = ecKeyTester.testECDSA(ecPrivKey, ecPubKey, m_ramArray, (short) 0, (short) (ARRAY_LENGTH / 2), m_ramArray2, (short) 0);
        Util.setShort(buffer, outputOffset, sw);
        outputOffset += 2;
        if (sw != ISO7816.SW_NO_ERROR) {
            return (short) (outputOffset - startOffset);
        }

        return (short) (outputOffset - startOffset);
    }

    /**
     * Receives an FP or F2M elliptic curve parameters in the APDU.
     * Then allocates a new keypair, sets said curve and tries ECDH, ECDSA.
     * APDU format:
     * byte CLA = CLA_SIMPLEECCAPPLET
     * byte INS = INS_TESTECSUPPORT_EXTERNAL
     * byte P0
     * byte P1
     * <p>
     * CDATA:
     * byte keyClass -> KeyPair.ALG_EC_FP or KeyPair.ALG_EC_F2\M
     * short keyLength
     * short fieldLength
     * short aLength
     * short bLength
     * short gxLength
     * short gyLength
     * short rLength
     * field -> FP: prime / F2M: three or one short representing the reduction polynomial
     * a
     * b
     * gx
     * gy
     * r
     * short k
     * <p>
     * Response APDU format:
     * CDATA:
     * byte ECTEST_SEPARATOR
     * byte ECTEST_ALLOCATE_KEYPAIR
     * short sw
     * byte ECTEST_SET_EXTERNALCURVE
     * short sw
     * byte ECTEST_GENERATE_KEYPAIR_EXTERNALCURVE
     * short sw
     * byte ECTEST_ECDH_AGREEMENT_VALID_POINT
     * short sw
     * byte ECTEST_ECDH_AGREEMENT_INVALID_POINT
     * short sw
     * byte ECTEST_ECDSA_SIGNATURE
     * short sw
     *
     * @param apdu
     */
    void TestEC_SupportExternal(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        short offset = ISO7816.OFFSET_CDATA;
        byte keyClass = apdubuf[offset];
        ++offset;
        short keyLength = Util.getShort(apdubuf, offset);
        offset += 2;

        short dataLength = TestECSupportExternalCurve(keyClass, keyLength, apdubuf, offset, (short) 0);

        apdu.setOutgoingAndSend((short) 0, dataLength);
    }


    void TestEC_FP_GenerateInvalidCurve(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        short offset = ISO7816.OFFSET_CDATA;
        short repeats = Util.getShort(apdubuf, offset);
        offset += 2;
        short corruptionType = Util.getShort(apdubuf, offset);
        offset += 2;
        byte bRewindOnSuccess = apdubuf[offset];
        offset++;

        short dataOffset = 0;

        // FP
        dataOffset += TestECSupportInvalidCurve(KeyPair.ALG_EC_FP, (short) 160, apdubuf, dataOffset, repeats, corruptionType, bRewindOnSuccess);

        apdu.setOutgoingAndSend((short) 0, dataOffset);
    }

    short TestECSupportInvalidCurve(byte keyClass, short keyLen, byte[] buffer, short bufferOffset, short repeats, short corruptionType, byte bRewindOnSuccess) {
        short baseOffset = bufferOffset;

        short testFlags = FLAG_ECTEST_ALL;

        ecPubKey = null;
        ecPrivKey = null;

        buffer[bufferOffset] = ECTEST_SEPARATOR;
        bufferOffset++;
        buffer[bufferOffset] = keyClass;
        bufferOffset++;
        Util.setShort(buffer, bufferOffset, keyLen);
        bufferOffset += 2;

        short numExecutionsOffset = bufferOffset; // num executions to be stored later
        bufferOffset += 2;

        short sw;

        //
        // 1. Allocate KeyPair object
        //
        buffer[bufferOffset] = ECTEST_ALLOCATE_KEYPAIR;
        bufferOffset++;
        sw = SW_SKIPPED;
        if ((testFlags & FLAG_ECTEST_ALLOCATE_KEYPAIR) != (short) 0) {
            sw = ecKeyGenerator.allocatePair(keyClass, keyLen);
            if (sw == ISO7816.SW_NO_ERROR) {
                ecPrivKey = ecKeyGenerator.getPrivateKey();
                ecPubKey = ecKeyGenerator.getPublicKey();
            } else {
                testFlags = 0;
            }

            if (ecPubKey == null || ecPrivKey == null) {
                ecKeyGenerator.generatePair();
                ecPrivKey = ecKeyGenerator.getPrivateKey();
                ecPubKey = ecKeyGenerator.getPublicKey();
            }
        }
        Util.setShort(buffer, bufferOffset, sw);
        bufferOffset += 2;


        //
        // 2. Set invalid custom curve (many times)
        //
        sw = ecKeyGenerator.setCustomCurve(keyClass, keyLen, m_ramArray, (short) 0);
        ecPrivKey = ecKeyGenerator.getPrivateKey();
        ecPubKey = ecKeyGenerator.getPublicKey();

        m_lenB = ecPubKey.getB(m_ramArray2, (short) 0); //store valid B

        short startOffset = bufferOffset;
        short i;
        for (i = 0; i < repeats; i++) {
            if ((testFlags & FLAG_ECTEST_SET_INVALIDCURVE) != (short) 0) {
                if (bRewindOnSuccess == 1) {
                    // if nothing unexpected happened, rewind bufferOffset back again 
                    bufferOffset = startOffset;
                }

                ecPubKey.getB(m_ramArray2, (short) 0); //store valid B

                // set invalid curve
                buffer[bufferOffset] = ECTEST_SET_INVALIDCURVE;
                bufferOffset++;

                // Supported types of invalid curve:
                // CORRUPTION_NONE = 0x01, valid parameter
                // CORRUPTION_FIXED = 0x02, first and last byte changed to a fixed value
                // CORRUPTION_FULLRANDOM = 0x03, completely random parameter data
                // CORRUPTION_ONEBYTERANDOM = 0x04, one random byte randomly changed
                // CORRUPTION_ZERO = 0x05, parameter competely zero
                // CORRUPTION_ONE = 0x06, parameter completely one
                sw = ecKeyGenerator.setCustomInvalidCurve(keyClass, keyLen, ECKeyGenerator.KEY_BOTH, EC_Consts.PARAMETER_B, corruptionType, m_ramArray, (short) 0);
                Util.setShort(buffer, bufferOffset, sw);
                bufferOffset += 2;
                if (sw != ISO7816.SW_NO_ERROR) {
                    // if we reach this line, we are interested in value of B that caused incorrect response
                    break; // stop execution, return B
                }

                // Gen key pair with invalid curve

                buffer[bufferOffset] = ECTEST_GENERATE_KEYPAIR_INVALIDCUSTOMCURVE;
                bufferOffset++;
                // Should fail
                sw = ecKeyGenerator.generatePair();
                Util.setShort(buffer, bufferOffset, sw);
                bufferOffset += 2;

                if (sw == ISO7816.SW_NO_ERROR) {
                    // If this line is reached, we generated key pair - what should not happen
                    buffer[bufferOffset] = ECTEST_DH_GENERATESECRET;
                    bufferOffset++;

                    ecPrivKey = ecKeyGenerator.getPrivateKey();
                    ecPubKey = ecKeyGenerator.getPublicKey();

                    sw = ecKeyTester.testECDH_validPoint(ecPrivKey, ecPubKey, m_ramArray, (short) 0, m_ramArray2, (short) 0);
                    m_lenB = ecPubKey.getB(m_ramArray2, (short) 0); //store B
                    //TODO: note, according to the previous version of this method, sw should get appended to the buffer only if sw != SW_NO_ERROR
                    Util.setShort(buffer, bufferOffset, sw);
                    bufferOffset += 2;
                    break; //stop execution, return B
                }

                // Generate keypair with valid curve - to check that whole engine is not somehow blocked
                //   after previous attempt with invalid curve
                //
                // set valid curve
                buffer[bufferOffset] = ECTEST_SET_VALIDCURVE;
                bufferOffset++;
                sw = ecKeyGenerator.setCustomCurve(keyClass, keyLen, m_ramArray, (short) 0);

                Util.setShort(buffer, bufferOffset, sw);
                bufferOffset += 2;

                // Gen key pair with valid curve
                buffer[bufferOffset] = ECTEST_GENERATE_KEYPAIR_CUSTOMCURVE;
                bufferOffset++;

                sw = ecKeyGenerator.generatePair();
                Util.setShort(buffer, bufferOffset, sw);
                bufferOffset += 2;
                if (sw != ISO7816.SW_NO_ERROR) {
                    break;
                }

                // If we reach this line => everything was as expected
                // Rewind offset in array back (no storage of info about expected runs)
                // bufferOffset = startOffset; done at beginning
            } else {
                Util.setShort(buffer, bufferOffset, SW_SKIPPED);
                bufferOffset += 2;
            }
        }

        // Set number of executed repeats
        Util.setShort(buffer, numExecutionsOffset, i);

        return (short) (bufferOffset - baseOffset);
    }

    //TODO: generalize invalid B setting to all curve params
    void TestECSupportInvalidCurve_lastUsedParams(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        short offset = 0;
        Util.arrayCopyNonAtomic(m_ramArray2, (short) 0, apdubuf, offset, m_lenB);
        offset += m_lenB;

        apdu.setOutgoingAndSend((short) 0, offset);
    }

    void AllocateKeyPairReturnDefCurve(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        short bitLen = Util.getShort(apdubuf, ISO7816.OFFSET_CDATA);

        // Note: all locations should happen in constructor. But here it is intentional
        // as we like to test for result of allocation
        ecKeyGenerator.allocatePair(KeyPair.ALG_EC_FP, bitLen);

        // If required, generate also new key pair
        if (apdubuf[ISO7816.OFFSET_P1] == (byte) 1) {

            // If required, initialize curve parameters first
            if (apdubuf[ISO7816.OFFSET_P2] == (byte) 2) {
                ecKeyGenerator.setCustomCurve(KeyPair.ALG_EC_FP, bitLen, m_ramArray, (short) 0);
            }

            // Now generate new keypair with either default or custom curve
            ecKeyGenerator.generatePair();

            short len;
            short offset = 0;

            // Export curve public parameters
            offset += 2; // reserve space for length
            len = ecKeyGenerator.exportParameter(ECKeyGenerator.KEY_PUBLIC, EC_Consts.PARAMETER_FP, apdubuf, offset);
            Util.setShort(apdubuf, (short) (offset - 2), len);
            offset += len;
            offset += 2; // reserve space for length
            len = ecKeyGenerator.exportParameter(ECKeyGenerator.KEY_PUBLIC, EC_Consts.PARAMETER_A, apdubuf, offset);
            Util.setShort(apdubuf, (short) (offset - 2), len);
            offset += len;

            offset += 2; // reserve space for length
            len = ecKeyGenerator.exportParameter(ECKeyGenerator.KEY_PUBLIC, EC_Consts.PARAMETER_B, apdubuf, offset);
            Util.setShort(apdubuf, (short) (offset - 2), len);
            offset += len;
            offset += 2; // reserve space for length
            len = ecKeyGenerator.exportParameter(ECKeyGenerator.KEY_PUBLIC, EC_Consts.PARAMETER_R, apdubuf, offset);
            Util.setShort(apdubuf, (short) (offset - 2), len);
            offset += len;
            /*
             offset += 2; // reserve space for length
             len = ecPubKey.getW(apdubuf, offset);
             Util.setShort(apdubuf, (short) (offset - 2), len);
             offset += len;
             */
            apdu.setOutgoingAndSend((short) 0, offset);
        }
    }

    void DeriveECDHSecret(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();

        // Assumption: proper EC keyPair is already allocated
        // If public key point is provided, then use it 
        if (len == 0) {
            // if not provided, use build-in one (valid only for 192 only)
            Util.arrayCopyNonAtomic(EC192_FP_PUBLICW, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, (short) EC192_FP_PUBLICW.length);
            len = (short) EC192_FP_PUBLICW.length;
        }

        // Generate fresh EC keypair
        ecKeyGenerator.generatePair();
        ecPrivKey = ecKeyGenerator.getPrivateKey();

        if (dhKeyAgreement == null) {
            dhKeyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
        }
        dhKeyAgreement.init(ecPrivKey);
        short secretLen = 0;
        // Generate and export secret 
        secretLen = dhKeyAgreement.generateSecret(apdubuf, ISO7816.OFFSET_CDATA, len, m_ramArray, (short) 0);
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, (short) 0, secretLen);

        apdu.setOutgoingAndSend((short) 0, secretLen);
    }

    void GenerateAndReturnKey(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        short offset = ISO7816.OFFSET_CDATA;
        byte keyClass = apdubuf[offset];
        offset++;

        short keyLength = Util.getShort(apdubuf, offset);
        offset += 2;

        byte anomalous = apdubuf[offset];

        offset = 0;

        switch (apdubuf[ISO7816.OFFSET_P1]) {
            case P1_SETCURVE: {
                ecKeyGenerator.allocatePair(keyClass, keyLength);

                if (anomalous != 0) {
                    ecKeyGenerator.setCustomAnomalousCurve(keyClass, keyLength, m_ramArray, (short) 0);
                } else {
                    ecKeyGenerator.setCustomCurve(keyClass, keyLength, m_ramArray, (short) 0);
                }
                ecKeyGenerator.generatePair();
                ecPubKey = ecKeyGenerator.getPublicKey();
                ecPrivKey = ecKeyGenerator.getPrivateKey();
                break;
            }
            case P1_GENERATEKEYPAIR: {
                // Assumption: proper EC keyPair is already allocated and initialized
                short sw = ecKeyGenerator.generatePair();
                if (sw != ISO7816.SW_NO_ERROR) {
                    ISOException.throwIt(sw);
                }
                ecPubKey = ecKeyGenerator.getPublicKey();
                ecPrivKey = ecKeyGenerator.getPrivateKey();

                offset = 0;
                apdubuf[offset] = EC_Consts.TAG_ECPUBKEY;
                offset++;
                offset += 2; // reserve space for length
                short len = ecKeyGenerator.exportParameter(ECKeyGenerator.KEY_PUBLIC, EC_Consts.PARAMETER_W, apdubuf, offset);
                Util.setShort(apdubuf, (short) (offset - 2), len);
                offset += len;
                apdubuf[offset] = EC_Consts.TAG_ECPRIVKEY;
                offset++;
                offset += 2; // reserve space for length
                len = ecKeyGenerator.exportParameter(ECKeyGenerator.KEY_PRIVATE, EC_Consts.PARAMETER_S, apdubuf, offset);
                Util.setShort(apdubuf, (short) (offset - 2), len);
                offset += len;
                break;
            }
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        apdu.setOutgoingAndSend((short) 0, offset);
    }
    
/*    
    void AllocateKeyPair(byte algorithm, short bitLen) {
        // Select proper attributes
        switch (bitLen) {
            case (short) 128: {
                ecKeyPair = ecKeyPair128;
                ecKeyPair = ecKeyPair128;
                ecPrivKey = ecPrivKey128;
                break;
            }
            case (short) 160: {
                ecKeyPair = ecKeyPair160;
                ecKeyPair = ecKeyPair160;
                ecPrivKey = ecPrivKey160;
                break;
            }
            case (short) 192: {
                ecKeyPair = ecKeyPair192;
                ecKeyPair = ecKeyPair192;
                ecPrivKey = ecPrivKey192;
                break;
            }
            case (short) 256: {
                ecKeyPair = ecKeyPair256;
                ecKeyPair = ecKeyPair256;
                ecPrivKey = ecPrivKey256;
                break;
            }
            default: {
                ISOException.throwIt((short) -1);
            }
        }
        
        // Allocate instance
        ecKeyPair = new KeyPair(algorithm, bitLen);
        ecKeyPair.genKeyPair();
        ecPubKey = (ECPublicKey) ecKeyPair.getPublic();
        // sometimes null is returned and previous one call to genKeyPair() 
        // is required before we can get public key
        if (ecPubKey == null) {
            ecKeyPair.genKeyPair();
        }
        ecPubKey = (ECPublicKey) ecKeyPair.getPublic();
        ecPrivKey = (ECPrivateKey) ecKeyPair.getPrivate();
        // Set required EC parameters 
        EC_Consts.setValidECKeyParams(ecPubKey, ecPrivKey, KeyPair.ALG_EC_FP, bitLen, m_ramArray);
    }
    

*/

}

