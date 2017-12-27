package cz.crcs.ectester.applet;


import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.security.*;

/**
 * Class capable of testing ECDH/C and ECDSA.
 * Note that ECDH and ECDHC output should equal, only the algorithm is different.
 *
 * @author Jan Jancar johny@neuromancer.sk
 */
public class ECKeyTester {
    private KeyAgreement ecKeyAgreement = null;
    private short kaType = 0;
    private Signature ecdsaSignature = null;
    private short sigType = 0;

    private short sw = ISO7816.SW_NO_ERROR;

    public short allocateKA(byte algorithm) {
        sw = ISO7816.SW_NO_ERROR;
        try {
            ecKeyAgreement = KeyAgreement.getInstance(algorithm, false);
            kaType = algorithm;
        } catch (CardRuntimeException ce) {
            sw = ce.getReason();
        }
        return sw;
    }

    public short allocateSig(byte algorithm) {
        sw = ISO7816.SW_NO_ERROR;
        try {
            ecdsaSignature = Signature.getInstance(algorithm, false);
            sigType = algorithm;
        } catch (CardRuntimeException ce) {
            sw = ce.getReason();
        }
        return sw;
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
    public short testKA(KeyPair privatePair, KeyPair publicPair, byte[] pubkeyBuffer, short pubkeyOffset, byte[] outputBuffer, short outputOffset, short corruption) {
        short length = 0;
        try {
            sw = AppletUtil.kaCheck(ecKeyAgreement);
            sw = AppletUtil.keypairCheck(privatePair);
            sw = AppletUtil.keypairCheck(publicPair);
            short pubkeyLength = ((ECPublicKey) publicPair.getPublic()).getW(pubkeyBuffer, pubkeyOffset);
            // reached ok
            ecKeyAgreement.init(privatePair.getPrivate()); // throws UNITIALIZED KEY when ALG_EC_SVDP_DHC_PLAIN is used
            //ISOException.throwIt((short) 0x666);

            pubkeyLength = EC_Consts.corruptParameter(corruption, pubkeyBuffer, pubkeyOffset, pubkeyLength);
            length = ecKeyAgreement.generateSecret(pubkeyBuffer, pubkeyOffset, pubkeyLength, outputBuffer, outputOffset);
        } catch (CardRuntimeException ce) {
            sw = ce.getReason();
        }
        return length;
    }

    /**
     * @param privatePair
     * @param pubkey
     * @param pubkeyOffset
     * @param pubkeyLength
     * @param outpuBuffer
     * @param outputOffset
     * @param corruption
     * @return
     */
    public short testKA_direct(KeyPair privatePair, byte[] pubkey, short pubkeyOffset, short pubkeyLength, byte[] outpuBuffer, short outputOffset, short corruption) {
        short length = 0;
        try {
            sw = AppletUtil.kaCheck(ecKeyAgreement);
            sw = AppletUtil.keypairCheck(privatePair);

            ecKeyAgreement.init(privatePair.getPrivate());
            pubkeyLength = EC_Consts.corruptParameter(corruption, pubkey, pubkeyOffset, pubkeyLength);
            length = ecKeyAgreement.generateSecret(pubkey, pubkeyOffset, pubkeyLength, outpuBuffer, outputOffset);
        } catch (CardRuntimeException ce) {
            sw = ce.getReason();
        }
        return length;
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
            sw = AppletUtil.signCheck(ecdsaSignature);

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

    public KeyAgreement getKA() {
        return ecKeyAgreement;
    }

    public Signature getSig() {
        return ecdsaSignature;
    }

    public boolean hasKA() {
        return ecKeyAgreement != null;
    }

    public boolean hasSig() {
        return ecdsaSignature != null;
    }

    public short getKaType() {
        return kaType;
    }

    public short getSigType() {
        return sigType;
    }

    public short getSW() {
        return sw;
    }
}
