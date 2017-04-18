package cz.crcs.ectester.applet;


import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import javacard.security.*;

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

    private short testKA(KeyAgreement ka, KeyPair privatePair, KeyPair publicPair, byte[] pubkeyBuffer, short pubkeyOffset, byte[] outputBuffer, short outputOffset, byte corruption) {
        short length = 0;
        try {
            sw = ECUtil.nullCheck(privatePair);
            sw = ECUtil.nullCheck(publicPair);

            ka.init(privatePair.getPrivate());
            short pubkeyLength = ((ECPublicKey) publicPair.getPublic()).getW(pubkeyBuffer, pubkeyOffset);
            pubkeyLength = EC_Consts.corruptParameter(corruption, pubkeyBuffer, pubkeyOffset, pubkeyLength);
            length = ka.generateSecret(pubkeyBuffer, pubkeyOffset, pubkeyLength, outputBuffer, outputOffset);
        } catch (CardRuntimeException ce) {
            sw = ce.getReason();
        }
        return length;
    }

    /**
     * Tests ECDH secret generation with keys from given {@code privatePair} and {@code publicPair}.
     * Uses {@code pubkeyBuffer} at {@code pubkeyOffset} for computations.
     * Output should equal with ECDHC output.
     *
     * @param privatePair
     * @param publicPair
     * @param pubkeyBuffer
     * @param pubkeyOffset
     * @param outputBuffer
     * @param outputOffset
     * @param corruption
     * @return derived secret length
     **/
    public short testECDH(KeyPair privatePair, KeyPair publicPair, byte[] pubkeyBuffer, short pubkeyOffset, byte[] outputBuffer, short outputOffset, byte corruption) {
        return testKA(ecdhKeyAgreement, privatePair, publicPair, pubkeyBuffer, pubkeyOffset, outputBuffer, outputOffset, corruption);
    }

    /**
     * Tests ECDHC secret generation with keys from given {@code privatePair} and {@code publicPair}.
     * Uses {@code pubkeyBuffer} at {@code pubkeyOffset} for computations.
     * Output should equal to ECDH output.
     *
     * @param privatePair
     * @param publicPair
     * @param pubkeyBuffer
     * @param pubkeyOffset
     * @param outputBuffer
     * @param outputOffset
     * @param corruption
     * @return derived secret length
     */
    public short testECDHC(KeyPair privatePair, KeyPair publicPair, byte[] pubkeyBuffer, short pubkeyOffset, byte[] outputBuffer, short outputOffset, byte corruption) {
        return testKA(ecdhcKeyAgreement, privatePair, publicPair, pubkeyBuffer, pubkeyOffset, outputBuffer, outputOffset, corruption);
    }

    /**
     *
     * @param privatePair
     * @param publicPair
     * @param pubkeyBuffer
     * @param pubkeyOffset
     * @param outputBuffer
     * @param outputOffset
     * @param corruption
     * @return
     */
    public short testECDH_ECDHC(KeyPair privatePair, KeyPair publicPair, byte[] pubkeyBuffer, short pubkeyOffset, byte[] outputBuffer, short outputOffset, byte corruption) {
        short ecdhLength = testECDH(privatePair, publicPair, pubkeyBuffer, pubkeyOffset, outputBuffer, outputOffset, corruption);
        if (sw != ISO7816.SW_NO_ERROR) {
            return ecdhLength;
        }
        short ecdhcLength = testECDHC(privatePair, publicPair, pubkeyBuffer, pubkeyOffset, outputBuffer, (short) (outputOffset + ecdhLength), corruption);
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
