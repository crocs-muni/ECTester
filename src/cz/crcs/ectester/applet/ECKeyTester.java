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

    private short testKA(KeyAgreement ka, KeyPair privatePair, KeyPair publicPair, byte[] pubkeyBuffer, short pubkeyOffset, byte[] outputBuffer, short outputOffset, short corruption) {
        short length = 0;
        try {
            sw = ECUtil.kaCheck(ka);
            sw = ECUtil.keypairCheck(privatePair);
            sw = ECUtil.keypairCheck(publicPair);

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
     * @param privatePair  KeyPair from which the private key is used
     * @param publicPair   KeyPair from which the public key is used
     * @param pubkeyBuffer buffer to be used for the public key
     * @param pubkeyOffset offset into pubkeyBuffer that can be used for the public key
     * @param outputBuffer buffer to be used for the secret output
     * @param outputOffset offset into the outputBuffer
     * @param corruption   (EC_Consts.CORRUPTION_* | ...)
     * @return derived secret length
     **/
    public short testECDH(KeyPair privatePair, KeyPair publicPair, byte[] pubkeyBuffer, short pubkeyOffset, byte[] outputBuffer, short outputOffset, short corruption) {
        return testKA(ecdhKeyAgreement, privatePair, publicPair, pubkeyBuffer, pubkeyOffset, outputBuffer, outputOffset, corruption);
    }

    /**
     * Tests ECDHC secret generation with keys from given {@code privatePair} and {@code publicPair}.
     * Uses {@code pubkeyBuffer} at {@code pubkeyOffset} for computations.
     * Output should equal to ECDH output.
     *
     * @param privatePair  KeyPair from which the private key is used
     * @param publicPair   KeyPair from which the public key is used
     * @param pubkeyBuffer buffer to be used for the public key
     * @param pubkeyOffset offset into pubkeyBuffer that can be used for the public key
     * @param outputBuffer buffer to be used for the secret output
     * @param outputOffset offset into the outputBuffer
     * @param corruption   (EC_Consts.CORRUPTION_* | ...)
     * @return derived secret length
     */
    public short testECDHC(KeyPair privatePair, KeyPair publicPair, byte[] pubkeyBuffer, short pubkeyOffset, byte[] outputBuffer, short outputOffset, short corruption) {
        return testKA(ecdhcKeyAgreement, privatePair, publicPair, pubkeyBuffer, pubkeyOffset, outputBuffer, outputOffset, corruption);
    }

    /**
     * @param privatePair  KeyPair from which the private key is used
     * @param publicPair   KeyPair from which the public key is used
     * @param pubkeyBuffer buffer to be used for the public key
     * @param pubkeyOffset offset into pubkeyBuffer that can be used for the public key
     * @param outputBuffer buffer to be used for the secret output
     * @param outputOffset offset into the outputBuffer
     * @param corruption   (EC_Consts.CORRUPTION_* | ...)
     * @return
     */
    public short testBOTH(KeyPair privatePair, KeyPair publicPair, byte[] pubkeyBuffer, short pubkeyOffset, byte[] outputBuffer, short outputOffset, short corruption) {
        short ecdhLength = testECDH(privatePair, publicPair, pubkeyBuffer, pubkeyOffset, outputBuffer, outputOffset, corruption);
        if (sw != ISO7816.SW_NO_ERROR) {
            return ecdhLength;
        }
        short ecdhcLength = testECDHC(privatePair, publicPair, pubkeyBuffer, pubkeyOffset, outputBuffer, (short) (outputOffset + ecdhLength), corruption);
        short length = (short) (ecdhLength + ecdhcLength);
        if (sw != ISO7816.SW_NO_ERROR) {
            return length;
        }
        if (Util.arrayCompare(outputBuffer, outputOffset, outputBuffer, (short) (outputOffset + ecdhLength), ecdhLength) != 0) {
            sw = ECTesterApplet.SW_DH_DHC_MISMATCH;
        }
        return length;

    }

    /**
     * @param privatePair  KeyPair from which the private key is used
     * @param publicPair   KeyPair from which the public key is used
     * @param pubkeyBuffer buffer to be used for the public key
     * @param pubkeyOffset offset into pubkeyBuffer that can be used for the public key
     * @param outputBuffer buffer to be used for the secret output
     * @param outputOffset offset into the outputBuffer
     * @param corruption   (EC_Consts.CORRUPTION_* | ...)
     * @return
     */
    public short testANY(KeyPair privatePair, KeyPair publicPair, byte[] pubkeyBuffer, short pubkeyOffset, byte[] outputBuffer, short outputOffset, short corruption) {
        short ecdhLength = testECDH(privatePair, publicPair, pubkeyBuffer, pubkeyOffset, outputBuffer, outputOffset, corruption);
        if (sw == ISO7816.SW_NO_ERROR)
            return ecdhLength;
        return testECDHC(privatePair, publicPair, pubkeyBuffer, pubkeyOffset, outputBuffer, outputOffset, corruption);
    }

    /**
     * Uses {@code signKey} to sign data from {@code inputBuffer} at {@code inputOffset} with {@code inputOffset}.
     * Then checks for correct signature length.
     * Then tries verifying the data with {@code verifyKey}.
     *
     * @param signKey     key to use for signing
     * @param verifyKey   key to use for verifying the signature
     * @param inputBuffer buffer to sign data from
     * @param inputOffset offset into inputBuffer to sign data from
     * @param inputLength length of data to sign
     * @param sigBuffer   buffer to output signature to
     * @param sigOffset   offset into sigBuffer to output to
     * @return signature length
     */
    public short testECDSA(ECPrivateKey signKey, ECPublicKey verifyKey, byte[] inputBuffer, short inputOffset, short inputLength, byte[] sigBuffer, short sigOffset) {
        short length = 0;
        try {
            sw = ECUtil.signCheck(ecdsaSignature);

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
