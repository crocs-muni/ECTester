package cz.crcs.ectester.common.util;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import javacard.framework.ISO7816;
import javacard.security.CryptoException;

import static cz.crcs.ectester.applet.ECTesterApplet.*;

/**
 * @author Petr Svenda petr@svenda.com
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CardUtil {
    public static byte getKA(String name) {
        switch (name) {
            case "DH":
            case "ECDH":
                return ECTesterApplet.KeyAgreement_ALG_EC_SVDP_DH;
            case "DHC":
            case "ECDHC":
                return ECTesterApplet.KeyAgreement_ALG_EC_SVDP_DHC;
            default:
                return ECTesterApplet.KeyAgreement_ALG_EC_SVDP_DH;
        }
    }

    public static String getSWSource(short sw) {
        switch (sw) {
            case ISO7816.SW_NO_ERROR:
            case ISO7816.SW_APPLET_SELECT_FAILED:
            case ISO7816.SW_BYTES_REMAINING_00:
            case ISO7816.SW_CLA_NOT_SUPPORTED:
            case ISO7816.SW_COMMAND_NOT_ALLOWED:
            case ISO7816.SW_CONDITIONS_NOT_SATISFIED:
            case ISO7816.SW_CORRECT_LENGTH_00:
            case ISO7816.SW_DATA_INVALID:
            case ISO7816.SW_FILE_FULL:
            case ISO7816.SW_FILE_INVALID:
            case ISO7816.SW_FILE_NOT_FOUND:
            case ISO7816.SW_FUNC_NOT_SUPPORTED:
            case ISO7816.SW_INCORRECT_P1P2:
            case ISO7816.SW_INS_NOT_SUPPORTED:
            case ISO7816.SW_LOGICAL_CHANNEL_NOT_SUPPORTED:
            case ISO7816.SW_RECORD_NOT_FOUND:
            case ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED:
            case ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED:
            case ISO7816.SW_UNKNOWN:
            case ISO7816.SW_WARNING_STATE_UNCHANGED:
            case ISO7816.SW_WRONG_DATA:
            case ISO7816.SW_WRONG_LENGTH:
            case ISO7816.SW_WRONG_P1P2:
                return "ISO";
            case CryptoException.ILLEGAL_VALUE:
            case CryptoException.UNINITIALIZED_KEY:
            case CryptoException.NO_SUCH_ALGORITHM:
            case CryptoException.INVALID_INIT:
            case CryptoException.ILLEGAL_USE:
                return "CryptoException";
            case ECTesterApplet.SW_SIG_VERIFY_FAIL:
            case ECTesterApplet.SW_DH_DHC_MISMATCH:
            case ECTesterApplet.SW_KEYPAIR_NULL:
            case ECTesterApplet.SW_KA_NULL:
            case ECTesterApplet.SW_SIGNATURE_NULL:
            case ECTesterApplet.SW_OBJECT_NULL:
                return "ECTesterApplet";
            default:
                return "?";
        }
    }

    public static String getSW(short sw) {
        switch (sw) {
            case ISO7816.SW_APPLET_SELECT_FAILED:
                return "APPLET_SELECT_FAILED";
            case ISO7816.SW_BYTES_REMAINING_00:
                return "BYTES_REMAINING";
            case ISO7816.SW_CLA_NOT_SUPPORTED:
                return "CLA_NOT_SUPPORTED";
            case ISO7816.SW_COMMAND_NOT_ALLOWED:
                return "COMMAND_NOT_ALLOWED";
            case ISO7816.SW_CONDITIONS_NOT_SATISFIED:
                return "CONDITIONS_NOT_SATISFIED";
            case ISO7816.SW_CORRECT_LENGTH_00:
                return "CORRECT_LENGTH";
            case ISO7816.SW_DATA_INVALID:
                return "DATA_INVALID";
            case ISO7816.SW_FILE_FULL:
                return "FILE_FULL";
            case ISO7816.SW_FILE_INVALID:
                return "FILE_INVALID";
            case ISO7816.SW_FILE_NOT_FOUND:
                return "FILE_NOT_FOUND";
            case ISO7816.SW_FUNC_NOT_SUPPORTED:
                return "FUNC_NOT_SUPPORTED";
            case ISO7816.SW_INCORRECT_P1P2:
                return "INCORRECT_P1P2";
            case ISO7816.SW_INS_NOT_SUPPORTED:
                return "INS_NOT_SUPPORTED";
            case ISO7816.SW_LOGICAL_CHANNEL_NOT_SUPPORTED:
                return "LOGICAL_CHANNEL_NOT_SUPPORTED";
            case ISO7816.SW_RECORD_NOT_FOUND:
                return "RECORD_NOT_FOUND";
            case ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED:
                return "SECURE_MESSAGING_NOT_SUPPORTED";
            case ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED:
                return "SECURITY_STATUS_NOT_SATISFIED";
            case ISO7816.SW_UNKNOWN:
                return "UNKNOWN";
            case ISO7816.SW_WARNING_STATE_UNCHANGED:
                return "WARNING_STATE_UNCHANGED";
            case ISO7816.SW_WRONG_DATA:
                return "WRONG_DATA";
            case ISO7816.SW_WRONG_LENGTH:
                return "WRONG_LENGTH";
            case ISO7816.SW_WRONG_P1P2:
                return "WRONG_P1P2";
            case CryptoException.ILLEGAL_VALUE:
                return "ILLEGAL_VALUE";
            case CryptoException.UNINITIALIZED_KEY:
                return "UNINITIALIZED_KEY";
            case CryptoException.NO_SUCH_ALGORITHM:
                return "NO_SUCH_ALG";
            case CryptoException.INVALID_INIT:
                return "INVALID_INIT";
            case CryptoException.ILLEGAL_USE:
                return "ILLEGAL_USE";
            case ECTesterApplet.SW_SIG_VERIFY_FAIL:
                return "SIG_VERIFY_FAIL";
            case ECTesterApplet.SW_DH_DHC_MISMATCH:
                return "DH_DHC_MISMATCH";
            case ECTesterApplet.SW_KEYPAIR_NULL:
                return "KEYPAIR_NULL";
            case ECTesterApplet.SW_KA_NULL:
                return "KA_NULL";
            case ECTesterApplet.SW_SIGNATURE_NULL:
                return "SIGNATURE_NULL";
            case ECTesterApplet.SW_OBJECT_NULL:
                return "OBJECT_NULL";
            default:
                return "unknown";
        }
    }

    public static String getSWString(short sw) {
        if (sw == ISO7816.SW_NO_ERROR) {
            return "OK   (0x9000)";
        } else {
            String str = getSW(sw);
            return String.format("fail (%s, 0x%04x)", str, sw);
        }
    }

    public static String getCorruption(short corruptionType) {
        switch (corruptionType) {
            case EC_Consts.CORRUPTION_NONE:
                return "NONE";
            case EC_Consts.CORRUPTION_FIXED:
                return "FIXED";
            case EC_Consts.CORRUPTION_ONE:
                return "ONE";
            case EC_Consts.CORRUPTION_ZERO:
                return "ZERO";
            case EC_Consts.CORRUPTION_ONEBYTERANDOM:
                return "ONE_BYTE_RANDOM";
            case EC_Consts.CORRUPTION_FULLRANDOM:
                return "FULL_RANDOM";
            case EC_Consts.CORRUPTION_INCREMENT:
                return "INCREMENT";
            case EC_Consts.CORRUPTION_INFINITY:
                return "INFINITY";
            case EC_Consts.CORRUPTION_COMPRESS:
                return "COMPRESSED";
            case EC_Consts.CORRUPTION_MAX:
                return "MAX";
            default:
                return "unknown";
        }
    }

    public static String getKATypeString(byte kaType) {
        switch (kaType) {
            case KeyAgreement_ALG_EC_SVDP_DH:
                return "ALG_EC_SVDP_DH";
            case KeyAgreement_ALG_EC_SVDP_DH_PLAIN:
                return "ALG_EC_SVDP_DH_PLAIN";
            case KeyAgreement_ALG_EC_PACE_GM:
                return "ALG_EC_PACE_GM";
            case KeyAgreement_ALG_EC_SVDP_DH_PLAIN_XY:
                return "ALG_EC_SVDP_DH_PLAIN_XY";
            case KeyAgreement_ALG_EC_SVDP_DHC:
                return "ALG_EC_SVDP_DHC";
            case KeyAgreement_ALG_EC_SVDP_DHC_PLAIN:
                return "ALG_EC_SVDP_DHC_PLAIN";
            default:
                return "unknown";
        }
    }

    public static byte getKAType(String kaTypeString) {
        switch (kaTypeString) {
            case "ALG_EC_SVDP_DH":
                return KeyAgreement_ALG_EC_SVDP_DH;
            case "ALG_EC_SVDP_DH_PLAIN":
                return KeyAgreement_ALG_EC_SVDP_DH_PLAIN;
            case "ALG_EC_PACE_GM":
                return KeyAgreement_ALG_EC_PACE_GM;
            case "ALG_EC_SVDP_DH_PLAIN_XY":
                return KeyAgreement_ALG_EC_SVDP_DH_PLAIN_XY;
            case "ALG_EC_SVDP_DHC":
                return KeyAgreement_ALG_EC_SVDP_DHC;
            case "ALG_EC_SVDP_DHC_PLAIN":
                return KeyAgreement_ALG_EC_SVDP_DHC_PLAIN;
            default:
                return 0;
        }
    }

    public static byte parseKAType(String kaTypeString) {
        byte kaType;
        try {
            kaType = Byte.parseByte(kaTypeString);
        } catch (NumberFormatException nfex) {
            kaType = getKAType(kaTypeString);
        }
        return kaType;
    }

    public static String getSigTypeString(byte sigType) {
        switch (sigType) {
            case Signature_ALG_ECDSA_SHA:
                return "ALG_ECDSA_SHA";
            case Signature_ALG_ECDSA_SHA_224:
                return "ALG_ECDSA_SHA_224";
            case Signature_ALG_ECDSA_SHA_256:
                return "ALG_ECDSA_SHA_256";
            case Signature_ALG_ECDSA_SHA_384:
                return "ALG_ECDSA_SHA_384";
            case Signature_ALG_ECDSA_SHA_512:
                return "ALG_ECDSA_SHA_512";
            default:
                return "unknown";
        }
    }

    public static byte getSigType(String sigTypeString) {
        switch (sigTypeString) {
            case "ALG_ECDSA_SHA":
                return Signature_ALG_ECDSA_SHA;
            case "ALG_ECDSA_SHA_224":
                return Signature_ALG_ECDSA_SHA_224;
            case "ALG_ECDSA_SHA_256":
                return Signature_ALG_ECDSA_SHA_256;
            case "ALG_ECDSA_SHA_384":
                return Signature_ALG_ECDSA_SHA_384;
            case "ALG_ECDSA_SHA_512":
                return Signature_ALG_ECDSA_SHA_512;
            default:
                return 0;
        }
    }

    public static byte parseSigType(String sigTypeString) {
        byte sigType;
        try {
            sigType = Byte.parseByte(sigTypeString);
        } catch (NumberFormatException nfex) {
            sigType = getSigType(sigTypeString);
        }
        return sigType;
    }
}
