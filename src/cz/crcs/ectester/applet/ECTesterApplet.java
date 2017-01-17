/*
 * PACKAGEID: 4C6162616B417070
 * APPLETID: 4C6162616B4170706C6574
 */
package cz.crcs.ectester.applet;

import javacard.framework.*;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import javacard.security.RandomData;

/**
 * @author Petr Svenda petr@svenda.com
 * @author Jan Jancar johny@neuromancer.sk
 */
public class ECTesterApplet extends Applet {

    // MAIN INSTRUCTION CLASS
    public static final byte CLA_ECTESTERAPPLET = (byte) 0xB0;

    //INSTRUCTIONS
    public static final byte INS_ALLOCATE = (byte) 0x5a;
    public static final byte INS_SET = (byte) 0x5b;
    public static final byte INS_GENERATE = (byte) 0x5c;
    public static final byte INS_ECDH = (byte) 0x5d;
    public static final byte INS_ECDSA = (byte) 0x5e;

    //PARAMETERS for P1 and P2
    public static final byte KEYPAIR_LOCAL = (byte) 0x01;
    public static final byte KEYPAIR_REMOTE = (byte) 0x02;
    public static final byte KEYPAIR_BOTH = KEYPAIR_LOCAL | KEYPAIR_REMOTE;
    public static final byte EXPORT_PUBLIC = (byte) 0x04;
    public static final byte EXPORT_PRIVATE = (byte) 0x08;
    public static final byte EXPORT_BOTH = EXPORT_PUBLIC | EXPORT_PRIVATE;
    public static final byte EXPORT_ECDH = (byte) 0x10;
    public static final byte EXPORT_SIG = (byte) 0x20;

    //STATUS WORDS
    public static final short SW_SIG_VERIFY_FAIL = (short) 0x0ee1;


    private static final short ARRAY_LENGTH = (short) 0xff;
    // TEMPORARRY ARRAY IN RAM
    private byte ramArray[] = null;
    private byte ramArray2[] = null;
    // PERSISTENT ARRAY IN EEPROM
    private byte dataArray[] = null; // unused


    private RandomData randomData = null;

    private KeyPair localKeypair = null;
    private KeyPair remoteKeypair = null;
    private ECKeyTester keyTester = null;
    private ECKeyGenerator keyGenerator = null;

    protected ECTesterApplet(byte[] buffer, short offset, byte length) {
        if (length > 9) {
            /*
            short dataOffset = offset;
            // shift to privilege offset
            dataOffset += (short) (1 + buffer[offset]);
            // finally shift to Application specific offset
            dataOffset += (short) (1 + buffer[dataOffset]);
            // go to proprietary data
            dataOffset++;
            */

            ramArray = JCSystem.makeTransientByteArray(ARRAY_LENGTH, JCSystem.CLEAR_ON_RESET);
            ramArray2 = JCSystem.makeTransientByteArray(ARRAY_LENGTH, JCSystem.CLEAR_ON_RESET);

            dataArray = new byte[ARRAY_LENGTH];
            Util.arrayFillNonAtomic(dataArray, (short) 0, ARRAY_LENGTH, (byte) 0);

            randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
            EC_Consts.randomData = randomData;

            keyGenerator = new ECKeyGenerator();
            keyTester = new ECKeyTester();
            keyTester.allocateECDH();
            keyTester.allocateECDHC();
            keyTester.allocateECDSA();
        }
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        // applet instance creation
        new ECTesterApplet(bArray, bOffset, bLength);
    }

    public void process(APDU apdu) throws ISOException {
        // get the APDU buffer
        byte[] apduBuffer = apdu.getBuffer();

        // ignore the applet select command dispached to the process
        if (selectingApplet())
            return;

        if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_ECTESTERAPPLET) {
            switch (apduBuffer[ISO7816.OFFSET_INS]) {
                case INS_ALLOCATE:
                    insAllocate(apdu);
                    break;
                case INS_SET:
                    insSet(apdu);
                    break;
                case INS_GENERATE:
                    insGenerate(apdu);
                    break;
                case INS_ECDH:
                    insECDH(apdu);
                    break;
                case INS_ECDSA:
                    insECDSA(apdu);
                    break;
                default:
                    // The INS code is not supported by the dispatcher
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                    break;
            }
        } else ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }

    /**
     * Allocate local and remote keypairs.
     * returns allocate SWs
     *
     * @param apdu P1   = byte keypair (KEYPAIR_* | ...)
     *             P2   =
     *             DATA = short keyLength
     *             byte keyClass
     */
    private void insAllocate(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] apdubuf = apdu.getBuffer();

        byte keypair = apdubuf[ISO7816.OFFSET_P1];
        short keyLength = Util.getShort(apdubuf, ISO7816.OFFSET_CDATA);
        byte keyClass = apdubuf[ISO7816.OFFSET_CDATA + 2];

        short len = allocate(keypair, keyLength, keyClass, apdubuf, (short) 0);

        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * @param keypair   which keypair to use, local/remote (KEYPAIR_* | ...)
     * @param keyLength key length to set
     * @param keyClass  key class to allocate
     * @param buffer    apdu buffer
     * @param offset    offset into apdu buffer
     * @return length of data written to the buffer
     */
    private short allocate(byte keypair, short keyLength, byte keyClass, byte[] buffer, short offset) {
        short length = 0;
        if ((keypair & KEYPAIR_LOCAL) != 0) {
            localKeypair = keyGenerator.allocatePair(keyClass, keyLength);
            Util.setShort(buffer, offset, keyGenerator.getSW());
            length += 2;
        }

        if ((keypair & KEYPAIR_REMOTE) != 0) {
            remoteKeypair = keyGenerator.allocatePair(keyClass, keyLength);
            Util.setShort(buffer, (short) (offset + length), keyGenerator.getSW());
            length += 2;
        }

        return length;
    }

    /**
     * Sets curve parameters on local and remote keypairs.
     * returns setCurve SWs, set params if export
     *
     * @param apdu P1   = byte keypair (KEYPAIR_* | ...)
     *             P2   = byte export (EXPORT_* | KEYPAIR_*)
     *             DATA = byte curve (EC_Consts.CURVE_*)
     *             short params (EC_Consts.PARAMETER_* | ...)
     *             short corruptedParams (EC_Consts.PARAMETER_* | ...)
     *             byte corruptionType (EC_Consts.CORRUPTION_*)
     *             <p>
     *             if curveID = CURVE_EXTERNAL:
     *             [short param_length, byte[] param],
     *             for all params in params,
     *             in order: field,a,b,g,r,k,w,s
     */
    private void insSet(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] apdubuf = apdu.getBuffer();

        byte keypair = apdubuf[ISO7816.OFFSET_P1];
        byte export = apdubuf[ISO7816.OFFSET_P2];
        byte curve = apdubuf[ISO7816.OFFSET_CDATA];
        short params = Util.getShort(apdubuf, (short) (ISO7816.OFFSET_CDATA + 1));
        short corruptedParams = Util.getShort(apdubuf, (short) (ISO7816.OFFSET_CDATA + 3));
        byte corruptionType = apdubuf[(short) (ISO7816.OFFSET_CDATA + 5)];

        short len = 0;

        if ((keypair & KEYPAIR_LOCAL) != 0)
            len += set(localKeypair, curve, params, corruptedParams, corruptionType, apdubuf, (short) (ISO7816.OFFSET_CDATA + 6), (short) 0);
        if ((keypair & KEYPAIR_REMOTE) != 0)
            len += set(remoteKeypair, curve, params, corruptedParams, corruptionType, apdubuf, (short) (ISO7816.OFFSET_CDATA + 6), len);
        if ((export & KEYPAIR_LOCAL) != 0)
            len += export(localKeypair, export, params, apdubuf, len);
        if ((export & KEYPAIR_REMOTE) != 0)
            len += export(remoteKeypair, export, params, apdubuf, len);

        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * @param keypair    KeyPair to set params on
     * @param curve      curve to set (EC_Consts.CURVE_*)
     * @param params     parameters to set (EC_Consts.PARAMETER_* | ...)
     * @param corrupted  parameters to corrupt (EC_Consts.PARAMETER_* | ...)
     * @param corruption corruption type (EC_Consts.CORRUPTION_*)
     * @param buffer     buffer to read params from and write sw to
     * @param inOffset   input offset in buffer
     * @param outOffset  output offset in buffer
     * @return length of data written to the buffer
     */
    private short set(KeyPair keypair, byte curve, short params, short corrupted, byte corruption, byte[] buffer, short inOffset, short outOffset) {
        short sw = ISO7816.SW_NO_ERROR;

        switch (curve) {
            case EC_Consts.CURVE_default:
                //default, dont set anything
                break;
            case EC_Consts.CURVE_external:
                //external
                sw = keyGenerator.setExternalCurve(keypair, params, buffer, inOffset);
                break;
            default:
                //custom
                sw = keyGenerator.setCurve(keypair, curve, params, ramArray, (short) 0);
                break;
        }

        if (sw == ISO7816.SW_NO_ERROR)
            sw = keyGenerator.corruptCurve(keypair, corrupted, corruption, ramArray, (short) 0);
        Util.setShort(buffer, outOffset, sw);
        return 2;
    }

    /**
     * Generates the local and remote keypairs.
     * returns generate SWs, pubkey and privkey if export
     *
     * @param apdu P1   = byte keypair (KEYPAIR_* | ...)
     *             P2   = byte export (EXPORT_* | KEYPAIR_*)
     */
    private void insGenerate(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] apdubuf = apdu.getBuffer();

        byte keypair = apdubuf[ISO7816.OFFSET_P1];
        byte export = apdubuf[ISO7816.OFFSET_P2];

        short len = 0;
        if ((keypair & KEYPAIR_LOCAL) != 0)
            len += generate(localKeypair, apdubuf, (short) 0);
        if ((keypair & KEYPAIR_REMOTE) != 0)
            len += generate(remoteKeypair, apdubuf, len);
        if ((export & KEYPAIR_LOCAL) != 0)
            len += export(localKeypair, export, (short) (EC_Consts.PARAMETER_W | EC_Consts.PARAMETER_S), apdubuf, len);
        if ((export & KEYPAIR_REMOTE) != 0)
            len += export(remoteKeypair, export, (short) (EC_Consts.PARAMETER_W | EC_Consts.PARAMETER_S), apdubuf, len);

        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * @param keypair KeyPair to generate
     * @param buffer  buffer to write sw to
     * @param offset  output offset in buffer
     * @return length of data written to the buffer
     */
    private short generate(KeyPair keypair, byte[] buffer, short offset) {
        short sw = keyGenerator.generatePair(keypair);
        Util.setShort(buffer, offset, sw);

        return 2;
    }

    /**
     * @param keypair KeyPair to export from
     * @param export  which key to export from (EXPORT_PUBLIC | EXPORT_PRIVATE)
     * @param params  which params to export (EC_Consts.PARAMETER_* | ...)
     * @param buffer  buffer to export params to
     * @param offset  output offset in buffer
     * @return length of data written to the buffer
     */
    private short export(KeyPair keypair, byte export, short params, byte[] buffer, short offset) {
        short length = 0;

        if ((export & EXPORT_PUBLIC) != 0) {
            //export params from public
            length += keyGenerator.exportParameters(keypair, ECKeyGenerator.KEY_PUBLIC, params, buffer, offset);
        }

        if ((export & EXPORT_PRIVATE) != 0) {
            //export params from private
            length += keyGenerator.exportParameters(keypair, ECKeyGenerator.KEY_PRIVATE, params, buffer, (short) (offset + length));

        }
        return length;
    }

    /**
     * Does ECDH, between the pubkey specified in P1(local/remote) and the privkey specified in P2(local/remote).
     * returns deriveSecret SW, if export != 0 => short secretlen, byte[] secret
     *
     * @param apdu P1   = byte pubkey (KEYPAIR_*)
     *             P2   = byte privkey (KEYPAIR_*)
     *             DATA = byte export (EXPORT_ECDH || 0)
     *             byte invalid (00 = valid, !00 = invalid)
     */
    private void insECDH(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] apdubuf = apdu.getBuffer();

        byte pubkey = apdubuf[ISO7816.OFFSET_P1];
        byte privkey = apdubuf[ISO7816.OFFSET_P2];
        byte export = apdubuf[ISO7816.OFFSET_CDATA];
        byte invalid = apdubuf[(short) (ISO7816.OFFSET_CDATA + 1)];

        short len = ecdh(pubkey, privkey, export, invalid, apdubuf, (short) 0);

        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * @param pubkey  keypair to use for public key, (KEYPAIR_LOCAL || KEYPAIR_REMOTE)
     * @param privkey keypair to use for private key, (KEYPAIR_LOCAL || KEYPAIR_REMOTE)
     * @param export  whether to export ECDH secret
     * @param invalid whether to invalidate the pubkey before ECDH
     * @param buffer  buffer to write sw to, and export ECDH secret if (export & EXPORT_ECDH) != 0
     * @param offset  output offset in buffer
     * @return length of data written to the buffer
     */
    private short ecdh(byte pubkey, byte privkey, byte export, byte invalid, byte[] buffer, short offset) {
        short length = 0;

        KeyPair pub = ((pubkey & KEYPAIR_LOCAL) != 0) ? localKeypair : remoteKeypair;
        KeyPair priv = ((privkey & KEYPAIR_LOCAL) != 0) ? localKeypair : remoteKeypair;

        short secretLength;
        if (invalid != 0) {
            secretLength = keyTester.testECDH_invalidPoint((ECPrivateKey) priv.getPrivate(), (ECPublicKey) pub.getPublic(), ramArray, (short) 0, ramArray2, (short) 0);
        } else {
            secretLength = keyTester.testECDH_validPoint((ECPrivateKey) priv.getPrivate(), (ECPublicKey) pub.getPublic(), ramArray, (short) 0, ramArray2, (short) 0);
        }

        Util.setShort(buffer, offset, keyTester.getSW());
        length += 2;

        if ((export & EXPORT_ECDH) != 0) {
            Util.setShort(buffer, (short) (offset + length), secretLength);
            length += 2;
            Util.arrayCopyNonAtomic(ramArray2, (short) 0, buffer, (short) (offset + length), secretLength);
            length += secretLength;
        }

        return length;
    }

    /**
     * Does and ECDSA signature and verification on data provided, using the keypair in P1(local/remote).
     * returns ecdsa SW, if export != 0 => short signature_length, byte[] signature
     *
     * @param apdu P1   = byte keypair (KEYPAIR_*)
     *             P2   = byte export (EXPORT_SIG || 0)
     *             DATA = short data_length (00 = random data generated, !00 = data length)
     *             byte[] data
     */
    private void insECDSA(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] apdubuf = apdu.getBuffer();

        byte keypair = apdubuf[ISO7816.OFFSET_P1];
        byte export = apdubuf[ISO7816.OFFSET_P2];

        short len = ecdsa(keypair, export, apdubuf, ISO7816.OFFSET_CDATA, (short) 0);

        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * @param keypair   keypair to use for signing and verification (KEYPAIR_LOCAL || KEYPAIR_REMOTE)
     * @param export    whether to export ECDSA signature
     * @param buffer    buffer to write sw to, and export ECDSA signature if (export & EXPORT_SIG) != 0
     * @param inOffset  input offset in buffer
     * @param outOffset output offset in buffer
     * @return length of data written to the buffer
     */
    private short ecdsa(byte keypair, byte export, byte[] buffer, short inOffset, short outOffset) {
        short length = 0;

        short dataLength = Util.getShort(buffer, inOffset);
        if (dataLength == 0) { //no data to sign
            //generate random
            dataLength = 32;
            randomData.generateData(ramArray, (short) 0, dataLength);
        } else {
            Util.arrayCopyNonAtomic(buffer, (short) (inOffset + 2), ramArray, (short) 0, dataLength);
        }

        KeyPair sign = ((keypair & KEYPAIR_LOCAL) != 0) ? localKeypair : remoteKeypair;

        short signatureLength = keyTester.testECDSA((ECPrivateKey) sign.getPrivate(), (ECPublicKey) sign.getPublic(), ramArray, (short) 0, dataLength, ramArray2, (short) 0);
        Util.setShort(buffer, outOffset, keyTester.getSW());
        length += 2;

        if ((export & EXPORT_SIG) != 0) {
            Util.setShort(buffer, (short) (outOffset + length), signatureLength);
            length += 2;

            Util.arrayCopyNonAtomic(ramArray2, (short) 0, buffer, (short) (outOffset + length), signatureLength);
            length += signatureLength;
        }

        return length;
    }
}
