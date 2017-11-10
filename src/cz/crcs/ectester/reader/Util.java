package cz.crcs.ectester.reader;

import cz.crcs.ectester.applet.ECTesterApplet;
import static cz.crcs.ectester.applet.ECTesterApplet.KeyAgreement_ALG_EC_PACE_GM;
import static cz.crcs.ectester.applet.ECTesterApplet.KeyAgreement_ALG_EC_SVDP_DH;
import static cz.crcs.ectester.applet.ECTesterApplet.KeyAgreement_ALG_EC_SVDP_DHC;
import static cz.crcs.ectester.applet.ECTesterApplet.KeyAgreement_ALG_EC_SVDP_DHC_PLAIN;
import static cz.crcs.ectester.applet.ECTesterApplet.KeyAgreement_ALG_EC_SVDP_DH_PLAIN;
import static cz.crcs.ectester.applet.ECTesterApplet.KeyAgreement_ALG_EC_SVDP_DH_PLAIN_XY;
import cz.crcs.ectester.applet.EC_Consts;
import javacard.framework.ISO7816;
import javacard.security.CryptoException;

/**
 * Utility class, some byte/hex manipulation, convenient byte[] methods.
 *
 * @author Petr Svenda petr@svenda.com
 * @author Jan Jancar johny@neuromancer.sk
 */
public class Util {

    public static short getShort(byte[] array, int offset) {
        return (short) (((array[offset] & 0xFF) << 8) | (array[offset + 1] & 0xFF));
    }

    public static void setShort(byte[] array, int offset, short value) {
        array[offset + 1] = (byte) (value & 0xFF);
        array[offset] = (byte) ((value >> 8) & 0xFF);
    }

    public static int diffBytes(byte[] one, int oneOffset, byte[] other, int otherOffset, int length) {
        for (int i = 0; i < length; ++i) {
            byte a = one[i + oneOffset];
            byte b = other[i + otherOffset];
            if (a != b) {
                return i;
            }
        }
        return length;
    }

    public static boolean compareBytes(byte[] one, int oneOffset, byte[] other, int otherOffset, int length) {
        return diffBytes(one, oneOffset, other, otherOffset, length) == length;
    }

    public static boolean allValue(byte[] array, byte value) {
        for (byte a : array) {
            if (a != value)
                return false;
        }
        return true;
    }

    public static byte[] hexToBytes(String hex) {
        return hexToBytes(hex, true);
    }

    public static byte[] hexToBytes(String hex, boolean bigEndian) {
        hex = hex.replace(" ", "");
        int len = hex.length();
        StringBuilder sb = new StringBuilder();

        if (len % 2 == 1) {
            sb.append("0");
            ++len;
        }

        if (bigEndian) {
            sb.append(hex);
        } else {
            for (int i = 0; i < len / 2; ++i) {
                if (sb.length() >= 2) {
                    sb.insert(sb.length() - 2, hex.substring(2 * i, 2 * i + 2));
                } else {
                    sb.append(hex.substring(2 * i, 2 * i + 2));
                }

            }
        }

        String data = sb.toString();
        byte[] result = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            result[i / 2] = (byte) ((Character.digit(data.charAt(i), 16) << 4)
                    + (Character.digit(data.charAt(i + 1), 16)));
        }
        return result;
    }

    public static String byteToHex(byte data) {
        return String.format("%02x", data);
    }

    public static String bytesToHex(byte[] data) {
        return bytesToHex(data, true);
    }

    public static String bytesToHex(byte[] data, boolean addSpace) {
        return bytesToHex(data, 0, data.length, addSpace);
    }

    public static String bytesToHex(byte[] data, int offset, int len) {
        return bytesToHex(data, offset, len, true);
    }

    public static String bytesToHex(byte[] data, int offset, int len, boolean addSpace) {
        StringBuilder buf = new StringBuilder();
        for (int i = offset; i < (offset + len); i++) {
            buf.append(byteToHex(data[i]));
            if (addSpace && i != (offset + len - 1)) {
                buf.append(" ");
            }
        }
        return (buf.toString());
    }

    public static byte[] concatenate(byte[]... arrays) {
        int len = 0;
        for (byte[] array : arrays) {
            if (array == null)
                continue;
            len += array.length;
        }
        byte[] out = new byte[len];
        int offset = 0;
        for (byte[] array : arrays) {
            if (array == null || array.length == 0)
                continue;
            System.arraycopy(array, 0, out, offset, array.length);
            offset += array.length;
        }
        return out;
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

    public static String getKA(byte ka) {
        String algo = "";
        if ((ka & EC_Consts.KA_ECDH) != 0 || ka == EC_Consts.KA_ANY) {
            algo += "ECDH";
        }
        if (ka == EC_Consts.KA_BOTH) {
            algo += "+";
        } else if (ka == EC_Consts.KA_ANY) {
            algo += "/";
        }
        if ((ka & EC_Consts.KA_ECDHC) != 0 || ka == EC_Consts.KA_ANY) {
            algo += "ECDHC";
        }
        return algo;
    }
    
    public static String getKATypeString(byte kaType) {
        String kaTypeString = "unknown";
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
}
