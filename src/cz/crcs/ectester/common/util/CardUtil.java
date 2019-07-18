package cz.crcs.ectester.common.util;

import cz.crcs.ectester.applet.ECTesterApplet;
import cz.crcs.ectester.applet.EC_Consts;
import javacard.framework.ISO7816;
import javacard.security.CryptoException;
import javacard.security.KeyPair;

import java.util.LinkedList;
import java.util.List;

/**
 * @author Petr Svenda petr@svenda.com
 * @author Jan Jancar johny@neuromancer.sk
 */
public class CardUtil {
    public static byte getSig(String name) {
        switch (name) {
            case "SHA1":
                return EC_Consts.Signature_ALG_ECDSA_SHA;
            case "SHA224":
                return EC_Consts.Signature_ALG_ECDSA_SHA_224;
            case "SHA256":
                return EC_Consts.Signature_ALG_ECDSA_SHA_256;
            case "SHA384":
                return EC_Consts.Signature_ALG_ECDSA_SHA_384;
            case "SHA512":
                return EC_Consts.Signature_ALG_ECDSA_SHA_512;
            default:
                return EC_Consts.Signature_ALG_ECDSA_SHA;
        }
    }

    public static String getSigHashAlgo(byte sigType) {
        switch (sigType) {
            case EC_Consts.Signature_ALG_ECDSA_SHA:
                return "SHA1";
            case EC_Consts.Signature_ALG_ECDSA_SHA_224:
                return "SHA224";
            case EC_Consts.Signature_ALG_ECDSA_SHA_256:
                return "SHA256";
            case EC_Consts.Signature_ALG_ECDSA_SHA_384:
                return "SHA384";
            case EC_Consts.Signature_ALG_ECDSA_SHA_512:
                return "SHA512";
            default:
                return null;
        }
    }

    public static String getSigHashName(byte sigType) {
        switch (sigType) {
            case EC_Consts.Signature_ALG_ECDSA_SHA:
                return "SHA-1";
            case EC_Consts.Signature_ALG_ECDSA_SHA_224:
                return "SHA-224";
            case EC_Consts.Signature_ALG_ECDSA_SHA_256:
                return "SHA-256";
            case EC_Consts.Signature_ALG_ECDSA_SHA_384:
                return "SHA-384";
            case EC_Consts.Signature_ALG_ECDSA_SHA_512:
                return "SHA-512";
            default:
                return null;
        }
    }

    public static byte getKA(String name) {
        switch (name) {
            case "DH":
                return EC_Consts.KeyAgreement_ALG_EC_SVDP_DH;
            case "DHC":
                return EC_Consts.KeyAgreement_ALG_EC_SVDP_DHC;
            case "DH_PLAIN":
                return EC_Consts.KeyAgreement_ALG_EC_SVDP_DH_PLAIN;
            case "DHC_PLAIN":
                return EC_Consts.KeyAgreement_ALG_EC_SVDP_DHC_PLAIN;
            case "PACE_GM":
                return EC_Consts.KeyAgreement_ALG_EC_PACE_GM;
            case "DH_PLAIN_XY":
                return EC_Consts.KeyAgreement_ALG_EC_SVDP_DH_PLAIN_XY;
            default:
                return EC_Consts.KeyAgreement_ALG_EC_SVDP_DH;
        }
    }

    public static String getKexHashName(byte kexType) {
        switch (kexType) {
            case EC_Consts.KeyAgreement_ALG_EC_SVDP_DH:
            case EC_Consts.KeyAgreement_ALG_EC_SVDP_DHC:
                return "SHA1";
            default:
                return "NONE";
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
        int upper = (sw & 0xff00) >> 8;
        int lower = (sw & 0xff);
        switch (upper) {
            case 0xf1:
                return String.format("CryptoException(%d)", lower);
            case 0xf2:
                return String.format("SystemException(%d)", lower);
            case 0xf3:
                return String.format("PINException(%d)", lower);
            case 0xf4:
                return String.format("TransactionException(%d)", lower);
            case 0xf5:
                return String.format("CardRuntimeException(%d)", lower);
            default:
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
                    case ECTesterApplet.SW_Exception:
                        return "Exception";
                    case ECTesterApplet.SW_ArrayIndexOutOfBoundsException:
                        return "ArrayIndexOutOfBoundsException";
                    case ECTesterApplet.SW_ArithmeticException:
                        return "ArithmeticException";
                    case ECTesterApplet.SW_ArrayStoreException:
                        return "ArrayStoreException";
                    case ECTesterApplet.SW_NullPointerException:
                        return "NullPointerException";
                    case ECTesterApplet.SW_NegativeArraySizeException:
                        return "NegativeArraySizeException";
                    default:
                        return "unknown";
                }
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

    public static String getParams(short params) {
        if (params == 0) {
            return "";
        }
        List<String> ps = new LinkedList<>();
        short paramMask = EC_Consts.PARAMETER_FP;
        while (paramMask <= EC_Consts.PARAMETER_S) {
            short paramValue = (short) (paramMask & params);
            if (paramValue != 0) {
                switch (paramValue) {
                    case EC_Consts.PARAMETER_FP:
                        ps.add("P");
                        break;
                    case EC_Consts.PARAMETER_F2M:
                        ps.add("2^M");
                        break;
                    case EC_Consts.PARAMETER_A:
                        ps.add("A");
                        break;
                    case EC_Consts.PARAMETER_B:
                        ps.add("B");
                        break;
                    case EC_Consts.PARAMETER_G:
                        ps.add("G");
                        break;
                    case EC_Consts.PARAMETER_R:
                        ps.add("R");
                        break;
                    case EC_Consts.PARAMETER_K:
                        ps.add("K");
                        break;
                    case EC_Consts.PARAMETER_W:
                        ps.add("W");
                        break;
                    case EC_Consts.PARAMETER_S:
                        ps.add("S");
                        break;
                }
            }
            paramMask = (short) (paramMask << 1);
        }

        if (ps.size() != 0) {
            return "[" + String.join(",", ps) + "]";
        } else {
            return "unknown";
        }
    }

    public static String getTransformation(short transformationType) {
        if (transformationType == 0) {
            return "NONE";
        }
        List<String> names = new LinkedList<>();
        short transformationMask = 1;
        while (transformationMask <= EC_Consts.TRANSFORMATION_04_MASK) {
            short transformationValue = (short) (transformationMask & transformationType);
            if (transformationValue != 0) {
                switch (transformationValue) {
                    case EC_Consts.TRANSFORMATION_FIXED:
                        names.add("FIXED");
                        break;
                    case EC_Consts.TRANSFORMATION_ONE:
                        names.add("ONE");
                        break;
                    case EC_Consts.TRANSFORMATION_ZERO:
                        names.add("ZERO");
                        break;
                    case EC_Consts.TRANSFORMATION_ONEBYTERANDOM:
                        names.add("ONE_BYTE_RANDOM");
                        break;
                    case EC_Consts.TRANSFORMATION_FULLRANDOM:
                        names.add("FULL_RANDOM");
                        break;
                    case EC_Consts.TRANSFORMATION_INCREMENT:
                        names.add("INCREMENT");
                        break;
                    case EC_Consts.TRANSFORMATION_INFINITY:
                        names.add("INFINITY");
                        break;
                    case EC_Consts.TRANSFORMATION_COMPRESS:
                        names.add("COMPRESSED");
                        break;
                    case EC_Consts.TRANSFORMATION_COMPRESS_HYBRID:
                        names.add("HYBRID");
                        break;
                    case EC_Consts.TRANSFORMATION_04_MASK:
                        names.add("MASK(O4)");
                        break;
                    case EC_Consts.TRANSFORMATION_MAX:
                        names.add("MAX");
                        break;
                }
            }
            transformationMask = (short) ((transformationMask) << 1);
        }
        if (names.size() != 0) {
            return String.join(" + ", names);
        } else {
            return "unknown";
        }
    }

    public static String getKATypeString(byte kaType) {
        switch (kaType) {
            case EC_Consts.KeyAgreement_ALG_EC_SVDP_DH:
                return "ALG_EC_SVDP_DH";
            case EC_Consts.KeyAgreement_ALG_EC_SVDP_DH_PLAIN:
                return "ALG_EC_SVDP_DH_PLAIN";
            case EC_Consts.KeyAgreement_ALG_EC_PACE_GM:
                return "ALG_EC_PACE_GM";
            case EC_Consts.KeyAgreement_ALG_EC_SVDP_DH_PLAIN_XY:
                return "ALG_EC_SVDP_DH_PLAIN_XY";
            case EC_Consts.KeyAgreement_ALG_EC_SVDP_DHC:
                return "ALG_EC_SVDP_DHC";
            case EC_Consts.KeyAgreement_ALG_EC_SVDP_DHC_PLAIN:
                return "ALG_EC_SVDP_DHC_PLAIN";
            default:
                return "unknown";
        }
    }

    public static byte getKAType(String kaTypeString) {
        switch (kaTypeString) {
            case "DH":
            case "ALG_EC_SVDP_DH":
                return EC_Consts.KeyAgreement_ALG_EC_SVDP_DH;
            case "DH_PLAIN":
            case "ALG_EC_SVDP_DH_PLAIN":
                return EC_Consts.KeyAgreement_ALG_EC_SVDP_DH_PLAIN;
            case "PACE_GM":
            case "ALG_EC_PACE_GM":
                return EC_Consts.KeyAgreement_ALG_EC_PACE_GM;
            case "DH_PLAIN_XY":
            case "ALG_EC_SVDP_DH_PLAIN_XY":
                return EC_Consts.KeyAgreement_ALG_EC_SVDP_DH_PLAIN_XY;
            case "DHC":
            case "ALG_EC_SVDP_DHC":
                return EC_Consts.KeyAgreement_ALG_EC_SVDP_DHC;
            case "DHC_PLAIN":
            case "ALG_EC_SVDP_DHC_PLAIN":
                return EC_Consts.KeyAgreement_ALG_EC_SVDP_DHC_PLAIN;
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
            case EC_Consts.Signature_ALG_ECDSA_SHA:
                return "ALG_ECDSA_SHA";
            case EC_Consts.Signature_ALG_ECDSA_SHA_224:
                return "ALG_ECDSA_SHA_224";
            case EC_Consts.Signature_ALG_ECDSA_SHA_256:
                return "ALG_ECDSA_SHA_256";
            case EC_Consts.Signature_ALG_ECDSA_SHA_384:
                return "ALG_ECDSA_SHA_384";
            case EC_Consts.Signature_ALG_ECDSA_SHA_512:
                return "ALG_ECDSA_SHA_512";
            default:
                return "unknown";
        }
    }

    public static byte getSigType(String sigTypeString) {
        switch (sigTypeString) {
            case "ECDSA_SHA":
            case "ALG_ECDSA_SHA":
                return EC_Consts.Signature_ALG_ECDSA_SHA;
            case "ECDSA_SHA_224":
            case "ALG_ECDSA_SHA_224":
                return EC_Consts.Signature_ALG_ECDSA_SHA_224;
            case "ECDSA_SHA_256":
            case "ALG_ECDSA_SHA_256":
                return EC_Consts.Signature_ALG_ECDSA_SHA_256;
            case "ECDSA_SHA_384":
            case "ALG_ECDSA_SHA_384":
                return EC_Consts.Signature_ALG_ECDSA_SHA_384;
            case "ECDSA_SHA_512":
            case "ALG_ECDSA_SHA_512":
                return EC_Consts.Signature_ALG_ECDSA_SHA_512;
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

    public static String getKeyTypeString(byte keyClass) {
        switch (keyClass) {
            case KeyPair.ALG_EC_FP:
                return "ALG_EC_FP";
            case KeyPair.ALG_EC_F2M:
                return "ALG_EC_F2M";
            default:
                return "";
        }
    }

    public static String getCurveName(byte curve) {
        String result = "";
        switch (curve) {
            case EC_Consts.CURVE_default:
                result = "default";
                break;
            case EC_Consts.CURVE_external:
                result = "external";
                break;
            case EC_Consts.CURVE_secp112r1:
                result = "secp112r1";
                break;
            case EC_Consts.CURVE_secp128r1:
                result = "secp128r1";
                break;
            case EC_Consts.CURVE_secp160r1:
                result = "secp160r1";
                break;
            case EC_Consts.CURVE_secp192r1:
                result = "secp192r1";
                break;
            case EC_Consts.CURVE_secp224r1:
                result = "secp224r1";
                break;
            case EC_Consts.CURVE_secp256r1:
                result = "secp256r1";
                break;
            case EC_Consts.CURVE_secp384r1:
                result = "secp384r1";
                break;
            case EC_Consts.CURVE_secp521r1:
                result = "secp521r1";
                break;
            case EC_Consts.CURVE_sect163r1:
                result = "sect163r1";
                break;
            case EC_Consts.CURVE_sect233r1:
                result = "sect233r1";
                break;
            case EC_Consts.CURVE_sect283r1:
                result = "sect283r1";
                break;
            case EC_Consts.CURVE_sect409r1:
                result = "sect409r1";
                break;
            case EC_Consts.CURVE_sect571r1:
                result = "sect571r1";
                break;
        }
        return result;
    }

    public static String getParameterString(short params) {
        String what = "";
        if (params == EC_Consts.PARAMETERS_DOMAIN_F2M || params == EC_Consts.PARAMETERS_DOMAIN_FP) {
            what = "curve";
        } else if (params == EC_Consts.PARAMETER_W) {
            what = "pubkey";
        } else if (params == EC_Consts.PARAMETER_S) {
            what = "privkey";
        } else if (params == EC_Consts.PARAMETERS_KEYPAIR) {
            what = "keypair";
        } else {
            what = getParams(params);
        }
        return what;
    }
}
