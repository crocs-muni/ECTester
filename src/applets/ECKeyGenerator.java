package applets;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;

/**
 *
 */
public class ECKeyGenerator {

    private KeyPair ecKeyPair = null;
    private ECPrivateKey ecPrivateKey = null;
    private ECPublicKey ecPublicKey = null;

    public static final byte KEY_PUBLIC = 0x01;
    public static final byte KEY_PRIVATE = 0x02;
    public static final byte KEY_BOTH = KEY_PUBLIC | KEY_PRIVATE;


    public short allocatePair(byte keyClass, short keyLength) {
        short result = ISO7816.SW_NO_ERROR;
        try {
            ecKeyPair = new KeyPair(keyClass, keyLength);
            ecPublicKey = (ECPublicKey) ecKeyPair.getPublic();
            ecPrivateKey = (ECPrivateKey) ecKeyPair.getPrivate();
        } catch (CryptoException ce) {
            result = ce.getReason();
        } catch (Exception e) {
            result = ISO7816.SW_UNKNOWN;
        }
        return result;
    }

    public boolean isAllocated() {
        return ecKeyPair != null;
    }

    public short generatePair() {
        short result = ISO7816.SW_NO_ERROR;
        try {
            ecKeyPair.genKeyPair();
            ecPublicKey = (ECPublicKey) ecKeyPair.getPublic();
            ecPrivateKey = (ECPrivateKey) ecKeyPair.getPrivate();
        } catch (CryptoException ce) {
            result = ce.getReason();
        } catch (Exception e) {
            result = ISO7816.SW_UNKNOWN;
        }
        return result;
    }

    public short setCustomCurve(byte keyClass, short keyLength, byte[] buffer, short offset) {
        return setCustomCurve(EC_Consts.getCurve(keyClass, keyLength), buffer, offset);
    }

    public short setCustomCurve(byte curve, byte[] buffer, short offset) {
        byte alg = EC_Consts.getCurveType(curve);
        short sw = ISO7816.SW_NO_ERROR;
        short length;
        if (alg == KeyPair.ALG_EC_FP) {
            length = EC_Consts.getCurveParameter(curve, EC_Consts.PARAMETER_FP, buffer, offset);
            sw = setParameter(KEY_BOTH, EC_Consts.PARAMETER_FP, buffer, offset, length);
        } else if (alg == KeyPair.ALG_EC_F2M) {
            length = EC_Consts.getCurveParameter(curve, EC_Consts.PARAMETER_F2M, buffer, offset);
            sw = setParameter(KEY_BOTH, EC_Consts.PARAMETER_F2M, buffer, offset, length);
        }
        if (sw != ISO7816.SW_NO_ERROR) return sw;

        //go through all params
        short param = EC_Consts.PARAMETER_A;
        while (param <= EC_Consts.PARAMETER_K) {
            length = EC_Consts.getCurveParameter(curve, param, buffer, offset);
            sw = setParameter(KEY_BOTH, param, buffer, offset, length);
            if (sw != ISO7816.SW_NO_ERROR) break;
            param = (short) (param << 1);
        }
        return sw;
    }

    public short setCustomInvalidCurve(short keyClass, short keyLength, byte key, short param, short corruptionType, byte[] buffer, short offset) {
        return setCustomInvalidCurve(EC_Consts.getCurve(keyClass, keyLength), key, param, corruptionType, buffer, offset);
    }

    public short setCustomInvalidCurve(byte curve, byte key, short param, short corruptionType, byte[] buffer, short offset) {
        short sw = setCustomCurve(curve, buffer, offset);
        if (sw != ISO7816.SW_NO_ERROR) return sw;

        //go through param bit by bit, and invalidate all selected params
        short paramMask = 0x01;
        while (paramMask <= EC_Consts.PARAMETER_K) {
            short masked = (short) (paramMask & param);
            if (masked != 0) {
                short length = EC_Consts.getCorruptCurveParameter(curve, masked, buffer, offset, corruptionType);
                sw = setParameter(key, masked, buffer, offset, length);
                if (sw != ISO7816.SW_NO_ERROR) return sw;
            }
            paramMask = (short) (paramMask << 1);
        }
        return sw;
    }

    public short setCustomAnomalousCurve(short keyClass, short keyLength, byte[] buffer, short offset) {
        return setCustomCurve(EC_Consts.getAnomalousCurve(keyClass, keyLength), buffer, offset);
    }

    public short setParameter(byte key, short param, byte[] data, short offset, short length) {
        short result = ISO7816.SW_NO_ERROR;
        try {
            switch (param) {
                case EC_Consts.PARAMETER_FP: {
                    if ((key & KEY_PUBLIC) != 0) ecPublicKey.setFieldFP(data, offset, length);
                    if ((key & KEY_PRIVATE) != 0) ecPrivateKey.setFieldFP(data, offset, length);
                    break;
                }
                case EC_Consts.PARAMETER_F2M: {
                    if (length == 2) {
                        short i = Util.makeShort(data[offset], data[(short) (offset + 1)]);
                        if ((key & KEY_PUBLIC) != 0) ecPublicKey.setFieldF2M(i);
                        if ((key & KEY_PRIVATE) != 0) ecPrivateKey.setFieldF2M(i);
                    } else if (length == 6) {
                        short i1 = Util.makeShort(data[offset], data[(short) (offset + 1)]);
                        short i2 = Util.makeShort(data[(short) (offset + 2)], data[(short) (offset + 3)]);
                        short i3 = Util.makeShort(data[(short) (offset + 4)], data[(short) (offset + 5)]);
                        if ((key & KEY_PUBLIC) != 0) ecPublicKey.setFieldF2M(i1, i2, i3);
                        if ((key & KEY_PRIVATE) != 0) ecPrivateKey.setFieldF2M(i1, i2, i3);
                    } else {
                        result = ISO7816.SW_UNKNOWN;
                    }
                    break;
                }
                case EC_Consts.PARAMETER_A: {
                    if ((key & KEY_PUBLIC) != 0) ecPublicKey.setA(data, offset, length);
                    if ((key & KEY_PRIVATE) != 0) ecPrivateKey.setA(data, offset, length);
                    break;
                }
                case EC_Consts.PARAMETER_B: {
                    if ((key & KEY_PUBLIC) != 0) ecPublicKey.setB(data, offset, length);
                    if ((key & KEY_PRIVATE) != 0) ecPrivateKey.setB(data, offset, length);
                    break;
                }
                case EC_Consts.PARAMETER_G: {
                    if ((key & KEY_PUBLIC) != 0) ecPublicKey.setG(data, offset, length);
                    if ((key & KEY_PRIVATE) != 0) ecPrivateKey.setG(data, offset, length);
                    break;
                }
                case EC_Consts.PARAMETER_R: {
                    if ((key & KEY_PUBLIC) != 0) ecPublicKey.setR(data, offset, length);
                    if ((key & KEY_PRIVATE) != 0) ecPrivateKey.setR(data, offset, length);
                    break;
                }
                case EC_Consts.PARAMETER_K: {
                    if (length != 2) {
                        result = ISO7816.SW_UNKNOWN;
                    } else {
                        short k = Util.getShort(data, offset);
                        if ((key & KEY_PUBLIC) != 0) ecPublicKey.setK(k);
                        if ((key & KEY_PRIVATE) != 0) ecPrivateKey.setK(k);
                    }
                    break;
                }
                case EC_Consts.PARAMETER_S:
                    if ((key & KEY_PRIVATE) != 0) ecPrivateKey.setS(data, offset, length);
                    break;
                case EC_Consts.PARAMETER_W:
                    if ((key & KEY_PUBLIC) != 0) ecPublicKey.setW(data, offset, length);
                    break;
                default: {
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                }
            }
        } catch (CryptoException ce) {
            result = ce.getReason();
        } catch (Exception e) {
            result = ISO7816.SW_UNKNOWN;
        }
        return result;
    }

    public short setExternalCurve(byte key, byte keyClass, byte[] buffer, short offset, short fieldLength, short aLength, short bLength, short gxLength, short gyLength, short rLength) {
        short sw = ISO7816.SW_NO_ERROR;
        if (keyClass == KeyPair.ALG_EC_FP) {
            sw = setParameter(key, EC_Consts.PARAMETER_FP, buffer, offset, fieldLength);
        } else if (keyClass == KeyPair.ALG_EC_F2M) {
            sw = setParameter(key, EC_Consts.PARAMETER_F2M, buffer, offset, fieldLength);
        }
        if (sw != ISO7816.SW_NO_ERROR) return sw;

        offset += fieldLength;

        //go through all params
        sw = setParameter(key, EC_Consts.PARAMETER_A, buffer, offset, aLength);
        if (sw != ISO7816.SW_NO_ERROR) return sw;
        offset += aLength;
        sw = setParameter(key, EC_Consts.PARAMETER_B, buffer, offset, bLength);
        if (sw != ISO7816.SW_NO_ERROR) return sw;
        offset += bLength;

        sw = setParameter(key, EC_Consts.PARAMETER_G, buffer, offset, (short) (gxLength + gyLength));
        if (sw != ISO7816.SW_NO_ERROR) return sw;
        offset += gxLength + gyLength;


        sw = setParameter(key, EC_Consts.PARAMETER_R, buffer, offset, aLength);
        if (sw != ISO7816.SW_NO_ERROR) return sw;
        offset += rLength;

        sw = setParameter(key, EC_Consts.PARAMETER_K, buffer, offset, (short) 2);
        return sw;
    }

    public short exportParameter(byte key, short param, byte[] outputBuffer, short outputOffset) {
        if (key == KEY_BOTH) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        short length = 0;
        try {
            switch (param) {
                case EC_Consts.PARAMETER_FP:
                case EC_Consts.PARAMETER_F2M:
                    if ((key & KEY_PUBLIC) != 0) length = ecPublicKey.getField(outputBuffer, outputOffset);
                    if ((key & KEY_PRIVATE) != 0) length = ecPrivateKey.getField(outputBuffer, outputOffset);
                    break;
                case EC_Consts.PARAMETER_A:
                    if ((key & KEY_PUBLIC) != 0) length = ecPublicKey.getA(outputBuffer, outputOffset);
                    if ((key & KEY_PRIVATE) != 0) length = ecPrivateKey.getA(outputBuffer, outputOffset);
                    break;
                case EC_Consts.PARAMETER_B:
                    if ((key & KEY_PUBLIC) != 0) length = ecPublicKey.getB(outputBuffer, outputOffset);
                    if ((key & KEY_PRIVATE) != 0) length = ecPrivateKey.getB(outputBuffer, outputOffset);
                    break;
                case EC_Consts.PARAMETER_G:
                    if ((key & KEY_PUBLIC) != 0) length = ecPublicKey.getG(outputBuffer, outputOffset);
                    if ((key & KEY_PRIVATE) != 0) length = ecPrivateKey.getG(outputBuffer, outputOffset);
                    break;
                case EC_Consts.PARAMETER_R:
                    if ((key & KEY_PUBLIC) != 0) length = ecPublicKey.getR(outputBuffer, outputOffset);
                    if ((key & KEY_PRIVATE) != 0) length = ecPrivateKey.getR(outputBuffer, outputOffset);
                    break;
                case EC_Consts.PARAMETER_K:
                    if ((key & KEY_PUBLIC) != 0) Util.setShort(outputBuffer, outputOffset, ecPublicKey.getK());
                    if ((key & KEY_PRIVATE) != 0) Util.setShort(outputBuffer, outputOffset, ecPrivateKey.getK());
                    length = 2;
                    break;
                case EC_Consts.PARAMETER_S:
                    if ((key & KEY_PRIVATE) != 0) length = ecPrivateKey.getS(outputBuffer, outputOffset);
                    break;
                case EC_Consts.PARAMETER_W:
                    if ((key & KEY_PUBLIC) != 0) length = ecPublicKey.getW(outputBuffer, outputOffset);
                default:
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
        } catch (CryptoException ce) {
            ISOException.throwIt(ce.getReason());
        } catch (Exception e) {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        return length;
    }

    public ECPrivateKey getPrivateKey() {
        return ecPrivateKey;
    }

    public ECPublicKey getPublicKey() {
        return ecPublicKey;
    }

    public KeyPair getKeyPair() {
        return ecKeyPair;
    }
}
