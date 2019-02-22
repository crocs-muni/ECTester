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
    private boolean dryRun = false;

    public short allocateKA(byte algorithm) {
        sw = ISO7816.SW_NO_ERROR;
        try {
            if (!dryRun) {
                ecKeyAgreement = KeyAgreement.getInstance(algorithm, false);
                kaType = algorithm;
            }
        } catch (CardRuntimeException ce) {
            sw = ce.getReason();
        }
        return sw;
    }

    public short allocateSig(byte algorithm) {
        sw = ISO7816.SW_NO_ERROR;
        try {
            if (!dryRun) {
                ecdsaSignature = Signature.getInstance(algorithm, false);
                sigType = algorithm;
            }
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
     * @param privatePair    KeyPair from which the private key is used
     * @param publicPair     KeyPair from which the public key is used
     * @param pubkeyBuffer   buffer to be used for the public key
     * @param pubkeyOffset   offset into pubkeyBuffer that can be used for the public key
     * @param outputBuffer   buffer to be used for the secret output
     * @param outputOffset   offset into the outputBuffer
     * @param transformation (EC_Consts.TRANSFORMATION_* | ...)
     * @return derived secret length
     **/
    public short testKA(KeyPair privatePair, KeyPair publicPair, byte[] pubkeyBuffer, short pubkeyOffset, byte[] outputBuffer, short outputOffset, short transformation) {
        short length = 0;
        try {
            sw = AppletUtil.kaCheck(ecKeyAgreement);
            sw = AppletUtil.keypairCheck(privatePair);
            sw = AppletUtil.keypairCheck(publicPair);
            if (!dryRun) {
                short pubkeyLength = ((ECPublicKey) publicPair.getPublic()).getW(pubkeyBuffer, pubkeyOffset);
                ecKeyAgreement.init(privatePair.getPrivate());

                pubkeyLength = EC_Consts.transformParameter(transformation, pubkeyBuffer, pubkeyOffset, pubkeyLength);
                length = ecKeyAgreement.generateSecret(pubkeyBuffer, pubkeyOffset, pubkeyLength, outputBuffer, outputOffset);
            }
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
     * @param transformation
     * @return
     */
    public short testKA_direct(KeyPair privatePair, byte[] pubkey, short pubkeyOffset, short pubkeyLength, byte[] outpuBuffer, short outputOffset, short transformation) {
        short length = 0;
        try {
            sw = AppletUtil.kaCheck(ecKeyAgreement);
            sw = AppletUtil.keypairCheck(privatePair);

            if (!dryRun) {
                ecKeyAgreement.init(privatePair.getPrivate());
                pubkeyLength = EC_Consts.transformParameter(transformation, pubkey, pubkeyOffset, pubkeyLength);
                length = ecKeyAgreement.generateSecret(pubkey, pubkeyOffset, pubkeyLength, outpuBuffer, outputOffset);
            }
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

            if (!dryRun) {
                ecdsaSignature.init(signKey, Signature.MODE_SIGN);
                length = ecdsaSignature.sign(inputBuffer, inputOffset, inputLength, sigBuffer, sigOffset);

                ecdsaSignature.init(verifyKey, Signature.MODE_VERIFY);
                if (!ecdsaSignature.verify(inputBuffer, inputOffset, inputLength, sigBuffer, sigOffset, length)) {
                    sw = AppletBase.SW_SIG_VERIFY_FAIL;
                }
            }
        } catch (CardRuntimeException ce) {
            sw = ce.getReason();
        }
        return length;
    }

    /**
     * @param signKey
     * @param inputBuffer
     * @param inputOffset
     * @param inputLength
     * @param sigBuffer
     * @param sigOffset
     * @return
     */
    public short testECDSA_sign(ECPrivateKey signKey, byte[] inputBuffer, short inputOffset, short inputLength, byte[] sigBuffer, short sigOffset) {
        short length = 0;
        try {
            sw = AppletUtil.signCheck(ecdsaSignature);

            if (!dryRun) {
                ecdsaSignature.init(signKey, Signature.MODE_SIGN);
                length = ecdsaSignature.sign(inputBuffer, inputOffset, inputLength, sigBuffer, sigOffset);
            }
        } catch (CardRuntimeException ce) {
            sw = ce.getReason();
        }
        return length;
    }

    /**
     * @param verifyKey
     * @param inputBuffer
     * @param inputOffset
     * @param inputLength
     * @param sigBuffer
     * @param sigOffset
     * @param sigLength
     * @return
     */
    public short testECDSA_verify(ECPublicKey verifyKey, byte[] inputBuffer, short inputOffset, short inputLength, byte[] sigBuffer, short sigOffset, short sigLength) {
        short length = 0;
        try {
            sw = AppletUtil.signCheck(ecdsaSignature);

            if (!dryRun) {
                ecdsaSignature.init(verifyKey, Signature.MODE_VERIFY);
                if (!ecdsaSignature.verify(inputBuffer, inputOffset, inputLength, sigBuffer, sigOffset, sigLength)) {
                    sw = AppletBase.SW_SIG_VERIFY_FAIL;
                }
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

    public void setDryRun(boolean dryRun) {
        this.dryRun = dryRun;
    }
}
