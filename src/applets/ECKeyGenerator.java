package applets;

import javacard.framework.ISO7816;
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

    public static final byte PARAMETER_FP = 1;
    public static final byte PARAMETER_F2M_ONE = 2;
    public static final byte PARAMETER_F2M_THREE = 3;
    public static final byte PARAMETER_A = 4;
    public static final byte PARAMETER_B = 5;
    public static final byte PARAMETER_G = 6;
    public static final byte PARAMETER_R = 7;
    public static final byte PARAMETER_K = 8;

    private static final byte PARAMETER_S = 9; //private key
    private static final byte PARAMETER_W = 10;//public key

    public static final byte KEY_PUBLIC = 0x1;
    public static final byte KEY_PRIVATE = 0x2;
    public static final byte KEY_BOTH = KEY_PUBLIC & KEY_PRIVATE;

    public short allocatePair(byte algorithm, short keyLength) {
        short result = ISO7816.SW_NO_ERROR;
        try {
            ecKeyPair = new KeyPair(algorithm, keyLength);
        } catch (CryptoException ce) {
            result = ce.getReason();
        } catch (Exception e) {
            result = ISO7816.SW_UNKNOWN;
        }
        return result;
    }

    public boolean isAlocated() {
        return ecKeyPair != null && ecPrivateKey != null && ecPublicKey != null;
    }

    public short generatePair() {
        short result = ISO7816.SW_NO_ERROR;
        try {
            ecKeyPair.genKeyPair();
            ecPrivateKey = (ECPrivateKey) ecKeyPair.getPrivate(); //TODO, do I want to keep private and pubkey separate from the keypair?
            ecPublicKey = (ECPublicKey) ecKeyPair.getPublic();
        } catch (CryptoException ce) {
            result = ce.getReason();
        } catch (Exception e) {
            result = ISO7816.SW_UNKNOWN;
        }
        return result;
    }

    public short setCustomCurve(byte keyClass, short keyLength) {
        //TODO
        return 0;
    }

    public short setCustomCurve(byte curve) {
        //TODO
        return 0;
    }

    public short setExternalParameter(byte key, byte param, byte[] data, short offset, short length) {
        short result = ISO7816.SW_NO_ERROR;
        try {
            switch (param) {
                case PARAMETER_FP:
                    if ((key & KEY_PRIVATE) != 0) ecPrivateKey.setFieldFP(data, offset, length);
                    if ((key & KEY_PUBLIC) != 0) ecPublicKey.setFieldFP(data, offset, length);
                    break;
                case PARAMETER_F2M_ONE:
                    if (length != 2) {
                        result = ISO7816.SW_UNKNOWN;
                    } else {
                        short i = Util.makeShort(data[offset], data[(short) (offset + 1)]);
                        if ((key & KEY_PRIVATE) != 0) ecPrivateKey.setFieldF2M(i);
                        if ((key & KEY_PUBLIC) != 0) ecPublicKey.setFieldF2M(i);
                    }
                    break;
                case PARAMETER_F2M_THREE:
                    if (length != 6) {
                        result = ISO7816.SW_UNKNOWN;
                    } else {
                        short i1 = Util.makeShort(data[offset], data[(short) (offset + 1)]);
                        short i2 = Util.makeShort(data[(short) (offset + 2)], data[(short) (offset + 3)]);
                        short i3 = Util.makeShort(data[(short) (offset + 4)], data[(short) (offset + 5)]);
                        if ((key & KEY_PRIVATE) != 0) ecPrivateKey.setFieldF2M(i1, i2, i3);
                        if ((key & KEY_PUBLIC) != 0) ecPublicKey.setFieldF2M(i1, i2, i3);
                    }
                    break;
                case PARAMETER_A:
                    if ((key & KEY_PRIVATE) != 0) ecPrivateKey.setA(data, offset, length);
                    if ((key & KEY_PUBLIC) != 0) ecPublicKey.setA(data, offset, length);
                    break;
                case PARAMETER_B:
                    if ((key & KEY_PRIVATE) != 0) ecPrivateKey.setB(data, offset, length);
                    if ((key & KEY_PUBLIC) != 0) ecPublicKey.setB(data, offset, length);
                    break;
                case PARAMETER_G:
                    if ((key & KEY_PRIVATE) != 0) ecPrivateKey.setG(data, offset, length);
                    if ((key & KEY_PUBLIC) != 0) ecPublicKey.setG(data, offset, length);
                    break;
                case PARAMETER_R:
                    if ((key & KEY_PRIVATE) != 0) ecPrivateKey.setR(data, offset, length);
                    if ((key & KEY_PUBLIC) != 0) ecPublicKey.setR(data, offset, length);
                    break;
                case PARAMETER_K:
                    if (length != 2) {
                        result = ISO7816.SW_UNKNOWN;
                    } else {
                        short k = Util.makeShort(data[offset], data[(short) (offset + 1)]);
                        if ((key & KEY_PRIVATE) != 0) ecPrivateKey.setK(k);
                        if ((key & KEY_PUBLIC) != 0) ecPublicKey.setK(k);
                    }
                    break;
                case PARAMETER_S:
                    if ((key & KEY_PRIVATE) != 0) ecPrivateKey.setS(data, offset, length);
                    break;
                case PARAMETER_W:
                    if ((key & KEY_PUBLIC) != 0) ecPublicKey.setW(data, offset, length);
                    break;
                default:
                    result = ISO7816.SW_UNKNOWN;
            }
        } catch (CryptoException ce) {
            result = ce.getReason();
        } catch (Exception e) {
            result = ISO7816.SW_UNKNOWN;
        }
        return result;
    }

    public short exportParameter(byte key, byte param, byte[] outputBuffer, short outputOffset) {
        if (key == KEY_BOTH) {
            return ISO7816.SW_UNKNOWN;
        }
        short result = ISO7816.SW_NO_ERROR;
        try {
            switch(param){
                case PARAMETER_FP:

                    break;

                default:

            }
        } catch (CryptoException ce) {

        } catch (Exception e) {

        }
        //TODO
        return result;
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
