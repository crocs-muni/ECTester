package cz.crcs.ectester.applet;


import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.Signature;

/**
 * Class capable of testing ECDH/C and ECDSA.
 * Note that ECDH and ECDHC output should equal, only the algorithm is different.
 *
 * @author Jan Jancar johny@neuromancer.sk
 */
public class ECKeyTester {

    private KeyAgreement ecdhKeyAgreement = null;
    private KeyAgreement ecdhcKeyAgreement = null;
    private Signature ecdsaSignature = null;

    private short sw = ISO7816.SW_NO_ERROR;

    public short allocateECDH() {
        sw = ISO7816.SW_NO_ERROR;
        try {
            ecdhKeyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
        } catch (CardRuntimeException ce) {
            sw = ce.getReason();
        }
        return sw;
    }

    public short allocateECDHC() {
        sw = ISO7816.SW_NO_ERROR;
        try {
            ecdhcKeyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DHC, false);
        } catch (CardRuntimeException ce) {
            sw = ce.getReason();
        }
        return sw;
    }

    public short allocateECDSA() {
        sw = ISO7816.SW_NO_ERROR;
        try {
            ecdsaSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
        } catch (CardRuntimeException ce) {
            sw = ce.getReason();
        }
        return sw;
    }

    private short testKA(KeyAgreement ka, ECPrivateKey privateKey, byte[] pubkeyBuffer, short pubkeyOffset, short pubkeyLength, byte[] outputBuffer, short outputOffset) {
        sw = ISO7816.SW_NO_ERROR;
        short length = 0;
        try {
            ka.init(privateKey);
            length = ka.generateSecret(pubkeyBuffer, pubkeyOffset, pubkeyLength, outputBuffer, outputOffset);
        } catch (CardRuntimeException ce) {
            sw = ce.getReason();
        }
        return length;
    }

    /**
     * Tests ECDH secret generation with given {@code privateKey} and {@code publicKey}.
     * Uses {@code pubkeyBuffer} at {@code pubkeyOffset} for computations.
     * Output should equal with ECDHC output.
     *
     * @param privateKey
     * @param publicKey
     * @param pubkeyBuffer
     * @param pubkeyOffset
     * @param outputBuffer
     * @param outputOffset
     * @param corruption
     * @return derived secret length
     **/
    public short testECDH(ECPrivateKey privateKey, ECPublicKey publicKey, byte[] pubkeyBuffer, short pubkeyOffset, byte[] outputBuffer, short outputOffset, byte corruption) {
        short length = publicKey.getW(pubkeyBuffer, pubkeyOffset);
        length = EC_Consts.corruptParameter(corruption, pubkeyBuffer, pubkeyOffset, length);
        return testKA(ecdhKeyAgreement, privateKey, pubkeyBuffer, pubkeyOffset, length, outputBuffer, outputOffset);
    }

    /**
     * Tests ECDHC secret generation with given {@code privateKey} and {@code publicKey}.
     * Uses {@code pubkeyBuffer} at {@code pubkeyOffset} for computations.
     * Output should equal to ECDH output.
     *
     * @param privateKey
     * @param publicKey
     * @param pubkeyBuffer
     * @param pubkeyOffset
     * @param outputBuffer
     * @param outputOffset
     * @param corruption
     * @return derived secret length
     */
    public short testECDHC(ECPrivateKey privateKey, ECPublicKey publicKey, byte[] pubkeyBuffer, short pubkeyOffset, byte[] outputBuffer, short outputOffset, byte corruption) {
        short length = publicKey.getW(pubkeyBuffer, pubkeyOffset);
        length = EC_Consts.corruptParameter(corruption, pubkeyBuffer, pubkeyOffset, length);
        return testKA(ecdhcKeyAgreement, privateKey, pubkeyBuffer, pubkeyOffset, length, outputBuffer, outputOffset);
    }

    /**
     *
     * @param privateKey
     * @param publicKey
     * @param pubkeyBuffer
     * @param pubkeyOffset
     * @param outputBuffer
     * @param outputOffset
     * @param corruption
     * @return
     */
    public short testKA(ECPrivateKey privateKey, ECPublicKey publicKey, byte[] pubkeyBuffer, short pubkeyOffset, byte[] outputBuffer, short outputOffset, byte corruption) {
        short ecdhLength = testECDH(privateKey, publicKey, pubkeyBuffer, pubkeyOffset, outputBuffer, outputOffset, corruption);
        if (sw != ISO7816.SW_NO_ERROR) {
            return ecdhLength;
        }
        short ecdhcLength = testECDHC(privateKey, publicKey, pubkeyBuffer, pubkeyOffset, outputBuffer, (short) (outputOffset + ecdhLength), corruption);
        short length = (short) (ecdhLength + ecdhcLength);
        if (sw != ISO7816.SW_NO_ERROR) {
            return length;
        }
        if (Util.arrayCompare(outputBuffer, outputOffset, outputBuffer, (short)(outputOffset + ecdhLength), ecdhLength) != 0) {
            sw = ECTesterApplet.SW_DH_DHC_MISMATCH;
        }
        return length;

    }

    /**
     * Uses {@code signKey} to sign data from {@code inputBuffer} at {@code inputOffset} with {@code inputOffset}.
     * Then checks for correct signature length.
     * Then tries verifying the data with {@code verifyKey}.
     *
     * @param signKey
     * @param verifyKey
     * @param inputBuffer
     * @param inputOffset
     * @param inputLength
     * @param sigBuffer
     * @param sigOffset
     * @return signature length
     */
    public short testECDSA(ECPrivateKey signKey, ECPublicKey verifyKey, byte[] inputBuffer, short inputOffset, short inputLength, byte[] sigBuffer, short sigOffset) {
        sw = ISO7816.SW_NO_ERROR;
        short length = 0;
        try {
            ecdsaSignature.init(signKey, Signature.MODE_SIGN);
            length = ecdsaSignature.sign(inputBuffer, inputOffset, inputLength, sigBuffer, sigOffset);

            ecdsaSignature.init(verifyKey, Signature.MODE_VERIFY);
            boolean correct = ecdsaSignature.verify(inputBuffer, inputOffset, inputLength, sigBuffer, sigOffset, length);
            if (!correct) {
                sw = ECTesterApplet.SW_SIG_VERIFY_FAIL;
            }
        } catch (CardRuntimeException ce) {
            sw = ce.getReason();
        }
        return length;
    }

    public KeyAgreement getECDH() {
        return ecdhKeyAgreement;
    }

    public KeyAgreement getECDHC() {
        return ecdhcKeyAgreement;
    }

    public Signature getECDSA() {
        return ecdsaSignature;
    }

    public boolean hasECDH() {
        return ecdhKeyAgreement != null;
    }

    public boolean hasECDHC() {
        return ecdhcKeyAgreement != null;
    }

    public boolean hasECDSA() {
        return ecdsaSignature != null;
    }

    public short getSW() {
        return sw;
    }

}
