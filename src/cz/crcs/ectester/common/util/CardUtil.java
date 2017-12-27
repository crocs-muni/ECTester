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
        }
        return ECTesterApplet.KeyAgreement_ALG_EC_SVDP_DH;
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
        String str;
        switch (sw) {
            case ISO7816.SW_APPLET_SELECT_FAILED:
                str = "APPLET_SELECT_FAILED";
                break;
            case ISO7816.SW_BYTES_REMAINING_00:
                str = "BYTES_REMAINING";
                break;
            case ISO7816.SW_CLA_NOT_SUPPORTED:
                str = "CLA_NOT_SUPPORTED";
                break;
            case ISO7816.SW_COMMAND_NOT_ALLOWED:
                str = "COMMAND_NOT_ALLOWED";
                break;
            case ISO7816.SW_CONDITIONS_NOT_SATISFIED:
                str = "CONDITIONS_NOT_SATISFIED";
                break;
            case ISO7816.SW_CORRECT_LENGTH_00:
                str = "CORRECT_LENGTH";
                break;
            case ISO7816.SW_DATA_INVALID:
                str = "DATA_INVALID";
                break;
            case ISO7816.SW_FILE_FULL:
                str = "FILE_FULL";
                break;
            case ISO7816.SW_FILE_INVALID:
                str = "FILE_INVALID";
                break;
            case ISO7816.SW_FILE_NOT_FOUND:
                str = "FILE_NOT_FOUND";
                break;
            case ISO7816.SW_FUNC_NOT_SUPPORTED:
                str = "FUNC_NOT_SUPPORTED";
                break;
            case ISO7816.SW_INCORRECT_P1P2:
                str = "INCORRECT_P1P2";
                break;
            case ISO7816.SW_INS_NOT_SUPPORTED:
                str = "INS_NOT_SUPPORTED";
                break;
            case ISO7816.SW_LOGICAL_CHANNEL_NOT_SUPPORTED:
                str = "LOGICAL_CHANNEL_NOT_SUPPORTED";
                break;
            case ISO7816.SW_RECORD_NOT_FOUND:
                str = "RECORD_NOT_FOUND";
                break;
            case ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED:
                str = "SECURE_MESSAGING_NOT_SUPPORTED";
                break;
            case ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED:
                str = "SECURITY_STATUS_NOT_SATISFIED";
                break;
            case ISO7816.SW_UNKNOWN:
                str = "UNKNOWN";
                break;
            case ISO7816.SW_WARNING_STATE_UNCHANGED:
                str = "WARNING_STATE_UNCHANGED";
                break;
            case ISO7816.SW_WRONG_DATA:
                str = "WRONG_DATA";
                break;
            case ISO7816.SW_WRONG_LENGTH:
                str = "WRONG_LENGTH";
                break;
            case ISO7816.SW_WRONG_P1P2:
                str = "WRONG_P1P2";
                break;
            case CryptoException.ILLEGAL_VALUE:
                str = "ILLEGAL_VALUE";
                break;
            case CryptoException.UNINITIALIZED_KEY:
                str = "UNINITIALIZED_KEY";
                break;
            case CryptoException.NO_SUCH_ALGORITHM:
                str = "NO_SUCH_ALG";
                break;
            case CryptoException.INVALID_INIT:
                str = "INVALID_INIT";
                break;
            case CryptoException.ILLEGAL_USE:
                str = "ILLEGAL_USE";
                break;
            case ECTesterApplet.SW_SIG_VERIFY_FAIL:
                str = "SIG_VERIFY_FAIL";
                break;
            case ECTesterApplet.SW_DH_DHC_MISMATCH:
                str = "DH_DHC_MISMATCH";
                break;
            case ECTesterApplet.SW_KEYPAIR_NULL:
                str = "KEYPAIR_NULL";
                break;
            case ECTesterApplet.SW_KA_NULL:
                str = "KA_NULL";
                break;
            case ECTesterApplet.SW_SIGNATURE_NULL:
                str = "SIGNATURE_NULL";
                break;
            case ECTesterApplet.SW_OBJECT_NULL:
                str = "OBJECT_NULL";
                break;
            default:
                str = "unknown";
                break;
        }
        return str;
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
        String corrupt;
        switch (corruptionType) {
            case EC_Consts.CORRUPTION_NONE:
                corrupt = "NONE";
                break;
            case EC_Consts.CORRUPTION_FIXED:
                corrupt = "FIXED";
                break;
            case EC_Consts.CORRUPTION_ONE:
                corrupt = "ONE";
                break;
            case EC_Consts.CORRUPTION_ZERO:
                corrupt = "ZERO";
                break;
            case EC_Consts.CORRUPTION_ONEBYTERANDOM:
                corrupt = "ONE_BYTE_RANDOM";
                break;
            case EC_Consts.CORRUPTION_FULLRANDOM:
                corrupt = "FULL_RANDOM";
                break;
            case EC_Consts.CORRUPTION_INCREMENT:
                corrupt = "INCREMENT";
                break;
            case EC_Consts.CORRUPTION_INFINITY:
                corrupt = "INFINITY";
                break;
            case EC_Consts.CORRUPTION_COMPRESS:
                corrupt = "COMPRESSED";
                break;
            case EC_Consts.CORRUPTION_MAX:
                corrupt = "MAX";
                break;
            default:
                corrupt = "unknown";
                break;
        }
        return corrupt;
    }

    public static String getKATypeString(byte kaType) {
        String kaTypeString;
        switch (kaType) {
            case KeyAgreement_ALG_EC_SVDP_DH:
                kaTypeString = "ALG_EC_SVDP_DH";
                break;
            case KeyAgreement_ALG_EC_SVDP_DH_PLAIN:
                kaTypeString = "ALG_EC_SVDP_DH_PLAIN";
                break;
            case KeyAgreement_ALG_EC_PACE_GM:
                kaTypeString = "ALG_EC_PACE_GM";
                break;
            case KeyAgreement_ALG_EC_SVDP_DH_PLAIN_XY:
                kaTypeString = "ALG_EC_SVDP_DH_PLAIN_XY";
                break;
            case KeyAgreement_ALG_EC_SVDP_DHC:
                kaTypeString = "ALG_EC_SVDP_DHC";
                break;
            case KeyAgreement_ALG_EC_SVDP_DHC_PLAIN:
                kaTypeString = "ALG_EC_SVDP_DHC_PLAIN";
                break;
            default:
                kaTypeString = "unknown";
        }
        return kaTypeString;
    }

    public static String getSigTypeString(byte sigType) {
        String sigTypeString;
        switch (sigType) {
            case Signature_ALG_ECDSA_SHA:
                sigTypeString = "ALG_ECDSA_SHA";
                break;
            case Signature_ALG_ECDSA_SHA_224:
                sigTypeString = "ALG_ECDSA_SHA_224";
                break;
            case Signature_ALG_ECDSA_SHA_256:
                sigTypeString = "ALG_ECDSA_SHA_256";
                break;
            case Signature_ALG_ECDSA_SHA_384:
                sigTypeString = "ALG_ECDSA_SHA_384";
                break;
            case Signature_ALG_ECDSA_SHA_512:
                sigTypeString = "ALG_ECDSA_SHA_512";
                break;
            default:
                sigTypeString = "unknown";
        }
        return sigTypeString;
    }
}
