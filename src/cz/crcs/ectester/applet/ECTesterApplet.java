/*
 * Copyright (c) 2016-2017 Petr Svenda <petr@svenda.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
/*
 * PACKAGEID: 4543546573746572
 * APPLETID: 45435465737465723031
 */
package cz.crcs.ectester.applet;

import javacard.framework.*;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import javacard.security.RandomData;

/**
 * Applet part of ECTester, a tool for testing Elliptic curve support on javacards.
 *
 * @author Petr Svenda petr@svenda.com
 * @author Jan Jancar johny@neuromancer.sk
 */
public class ECTesterApplet extends Applet {

    // MAIN INSTRUCTION CLASS
    public static final byte CLA_ECTESTERAPPLET = (byte) 0xB0;

    // INSTRUCTIONS
    public static final byte INS_ALLOCATE = (byte) 0x5a;
    public static final byte INS_CLEAR = (byte) 0x5b;
    public static final byte INS_SET = (byte) 0x5c;
    public static final byte INS_CORRUPT = (byte) 0x5d;
    public static final byte INS_GENERATE = (byte) 0x5e;
    public static final byte INS_EXPORT = (byte) 0x5f;
    public static final byte INS_ECDH = (byte) 0x60;
    public static final byte INS_ECDSA = (byte) 0x61;
    public static final byte INS_CLEANUP = (byte) 0x62;
    public static final byte INS_SUPPORT = (byte) 0x63;

    // PARAMETERS for P1 and P2
    public static final byte KEYPAIR_LOCAL = (byte) 0x01;
    public static final byte KEYPAIR_REMOTE = (byte) 0x02;
    public static final byte KEYPAIR_BOTH = KEYPAIR_LOCAL | KEYPAIR_REMOTE;
    public static final byte EXPORT_TRUE = (byte) 0xff;
    public static final byte EXPORT_FALSE = (byte) 0x00;

    // STATUS WORDS
    public static final short SW_SIG_VERIFY_FAIL = (short) 0x0ee1;


    private static final short ARRAY_LENGTH = (short) 0xff;
    // TEMPORARRY ARRAY IN RAM
    private byte[] ramArray = null;
    private byte[] ramArray2 = null;
    // PERSISTENT ARRAY IN EEPROM
    private byte[] dataArray = null; // unused


    private RandomData randomData = null;

    private ECKeyTester keyTester = null;
    private short ecdhSW;
    private short ecdhcSW;
    private short ecdsaSW;
    private ECKeyGenerator keyGenerator = null;
    private KeyPair localKeypair = null;
    private KeyPair remoteKeypair = null;

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
            ecdhSW = keyTester.allocateECDH();
            ecdhcSW = keyTester.allocateECDHC();
            ecdsaSW = keyTester.allocateECDSA();
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
        if (selectingApplet()) {
            return;
        }

        if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_ECTESTERAPPLET) {
            switch (apduBuffer[ISO7816.OFFSET_INS]) {
                case INS_ALLOCATE:
                    insAllocate(apdu);
                    break;
                case INS_CLEAR:
                    insClear(apdu);
                    break;
                case INS_SET:
                    insSet(apdu);
                    break;
                case INS_CORRUPT:
                    insCorrupt(apdu);
                    break;
                case INS_GENERATE:
                    insGenerate(apdu);
                    break;
                case INS_EXPORT:
                    insExport(apdu);
                    break;
                case INS_ECDH:
                    insECDH(apdu);
                    break;
                case INS_ECDSA:
                    insECDSA(apdu);
                    break;
                case INS_CLEANUP:
                    insCleanup(apdu);
                    break;
                case INS_SUPPORT:
                    insSupport(apdu);
                    break;
                default:
                    // The INS code is not supported by the dispatcher
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                    break;
            }
        } else ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }

    /**
     * Allocates local and remote keyPairs.
     * returns allocate SWs
     *
     * @param apdu P1   = byte keyPair (KEYPAIR_* | ...)
     *             P2   =
     *             DATA = short keyLength
     *             byte keyClass
     */
    private void insAllocate(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] apdubuf = apdu.getBuffer();

        byte keyPair = apdubuf[ISO7816.OFFSET_P1];
        short keyLength = Util.getShort(apdubuf, ISO7816.OFFSET_CDATA);
        byte keyClass = apdubuf[ISO7816.OFFSET_CDATA + 2];

        short len = allocate(keyPair, keyLength, keyClass, apdubuf, (short) 0);

        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * Clears local and remote keyPair's keys {@code .clearKey()}.
     * returns clearKey SWs
     *
     * @param apdu P1   = byte keyPair (KEYPAIR_* | ...)
     *             P2   =
     */
    private void insClear(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] apdubuf = apdu.getBuffer();
        byte keyPair = apdubuf[ISO7816.OFFSET_P1];

        short len = 0;
        if ((keyPair & KEYPAIR_LOCAL) != 0) {
            len += clear(localKeypair, apdubuf, (short) 0);
        }
        if ((keyPair & KEYPAIR_REMOTE) != 0) {
            len += clear(remoteKeypair, apdubuf, len);
        }

        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * Sets curve parameters on local and remote keyPairs.
     * returns setCurve SWs
     *
     * @param apdu P1   = byte keyPair (KEYPAIR_* | ...)
     *             P2   = byte curve (EC_Consts.CURVE_*)
     *             DATA = short params (EC_Consts.PARAMETER_* | ...)
     *             <p>
     *             if curveID = CURVE_EXTERNAL:
     *             [short paramLength, byte[] param],
     *             for all params in params,
     *             in order: field,a,b,g,r,k,w,s
     */
    private void insSet(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] apdubuf = apdu.getBuffer();

        byte keyPair = apdubuf[ISO7816.OFFSET_P1];
        byte curve = apdubuf[ISO7816.OFFSET_P2];
        short params = Util.getShort(apdubuf, ISO7816.OFFSET_CDATA);

        short len = 0;

        if ((keyPair & KEYPAIR_LOCAL) != 0) {
            len += set(localKeypair, curve, params, apdubuf, (short) (ISO7816.OFFSET_CDATA + 2), (short) 0);
        }
        if ((keyPair & KEYPAIR_REMOTE) != 0) {
            len += set(remoteKeypair, curve, params, apdubuf, (short) (ISO7816.OFFSET_CDATA + 2), len);
        }

        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * Corrupts curve paramaters of local and remote keyPairs.
     * returns corruptCurve SWs
     *
     * @param apdu P1 = byte keyPair (KEYPAIR_* | ...)
     *             P2 = byte key (EC_Consts.KEY_* | ...)
     *             DATA = short params (EC_Consts.PARAMETER_* | ...)
     *             byte corruption (EC_Consts.CORRUPTION_* || ...)
     */
    private void insCorrupt(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] apdubuf = apdu.getBuffer();

        byte keyPair = apdubuf[ISO7816.OFFSET_P1];
        byte key = apdubuf[ISO7816.OFFSET_P2];
        short params = Util.getShort(apdubuf, ISO7816.OFFSET_CDATA);
        byte corruption = apdubuf[(short) (ISO7816.OFFSET_CDATA + 2)];

        short len = 0;
        if ((keyPair & KEYPAIR_LOCAL) != 0) {
            len += corrupt(localKeypair, key, params, corruption, apdubuf, (short) 0);
        }

        if ((keyPair & KEYPAIR_REMOTE) != 0) {
            len += corrupt(remoteKeypair, key, params, corruption, apdubuf, len);
        }

        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * Generates the local and remote keyPairs.
     * returns generate SWs
     *
     * @param apdu P1   = byte keyPair (KEYPAIR_* | ...)
     *             P2   =
     */
    private void insGenerate(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] apdubuf = apdu.getBuffer();

        byte keyPair = apdubuf[ISO7816.OFFSET_P1];

        short len = 0;
        if ((keyPair & KEYPAIR_LOCAL) != 0) {
            len += generate(localKeypair, apdubuf, (short) 0);
        }
        if ((keyPair & KEYPAIR_REMOTE) != 0) {
            len += generate(remoteKeypair, apdubuf, len);
        }

        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * Exports selected key and domain parameters from the selected keyPair and key.
     *
     * @param apdu P1   = byte keyPair (KEYPAIR_* | ...)
     *             P2   = byte key (EC_Consts.KEY_* | ...)
     *             DATA = short params
     */
    private void insExport(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] apdubuf = apdu.getBuffer();

        byte keyPair = apdubuf[ISO7816.OFFSET_P1];
        byte key = apdubuf[ISO7816.OFFSET_P2];
        short params = Util.getShort(apdubuf, ISO7816.OFFSET_CDATA);

        short swOffset = 0;
        short len = (short) (keyPair == KEYPAIR_BOTH ? 4 : 2);

        if ((keyPair & KEYPAIR_LOCAL) != 0) {
            len += export(localKeypair, key, params, apdubuf, swOffset, len);
            swOffset += 2;
        }
        if ((keyPair & KEYPAIR_REMOTE) != 0) {
            len += export(remoteKeypair, key, params, apdubuf, swOffset, len);
        }

        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * Performs ECDH, between the pubkey specified in P1(local/remote) and the privkey specified in P2(local/remote).
     * returns deriveSecret SW, {@code if(export == EXPORT_TRUE)} => short secretlen, byte[] secret
     *
     * @param apdu P1   = byte pubkey (KEYPAIR_*)
     *             P2   = byte privkey (KEYPAIR_*)
     *             DATA = byte export (EXPORT_TRUE || EXPORT_FALSE)
     *             byte corruption (00 = valid, !00 = invalid)
     *             byte type (EC_Consts.KA_* | ...)
     */
    private void insECDH(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] apdubuf = apdu.getBuffer();

        byte pubkey = apdubuf[ISO7816.OFFSET_P1];
        byte privkey = apdubuf[ISO7816.OFFSET_P2];
        byte export = apdubuf[ISO7816.OFFSET_CDATA];
        byte corruption = apdubuf[(short) (ISO7816.OFFSET_CDATA + 1)];
        byte type = apdubuf[(short) (ISO7816.OFFSET_CDATA + 2)];

        short len = ecdh(pubkey, privkey, export, corruption, type, apdubuf, (short) 0);

        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * Performs ECDSA signature and verification on data provided or random, using the keyPair in P1(local/remote).
     * returns ecdsa SW, {@code if(export == EXPORT_TRUE)} => short signature_length, byte[] signature
     *
     * @param apdu P1   = byte keyPair (KEYPAIR_*)
     *             P2   = byte export (EXPORT_TRUE || EXPORT_FALSE)
     *             DATA = short dataLength (00 = random data generated, !00 = data length)
     *             byte[] data
     */
    private void insECDSA(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] apdubuf = apdu.getBuffer();

        byte keyPair = apdubuf[ISO7816.OFFSET_P1];
        byte export = apdubuf[ISO7816.OFFSET_P2];

        short len = 0;
        if ((keyPair & KEYPAIR_LOCAL) != 0) {
            len += ecdsa(localKeypair, export, apdubuf, ISO7816.OFFSET_CDATA, (short) 0);
        }
        if ((keyPair & KEYPAIR_REMOTE) != 0) {
            len += ecdsa(remoteKeypair, export, apdubuf, ISO7816.OFFSET_CDATA, len);
        }

        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     *
     * @param apdu
     */
    private void insCleanup(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] apdubuf = apdu.getBuffer();

        short len = cleanup(apdubuf, (short) 0);

        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     *
     * @param apdu
     */
    private void insSupport(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] apdubuf = apdu.getBuffer();

        short len = support(apdubuf, (short) 0);

        apdu.setOutgoingAndSend((short) 0, len);
    }

    /**
     * @param keyPair   which keyPair to use, local/remote (KEYPAIR_* | ...)
     * @param keyLength key length to set
     * @param keyClass  key class to allocate
     * @param buffer    buffer to write sw to
     * @param offset    offset into buffer
     * @return length of data written to the buffer
     */
    private short allocate(byte keyPair, short keyLength, byte keyClass, byte[] buffer, short offset) {
        short length = 0;
        if ((keyPair & KEYPAIR_LOCAL) != 0) {
            localKeypair = keyGenerator.allocatePair(keyClass, keyLength);
            Util.setShort(buffer, offset, keyGenerator.getSW());
            length += 2;
        }

        if ((keyPair & KEYPAIR_REMOTE) != 0) {
            remoteKeypair = keyGenerator.allocatePair(keyClass, keyLength);
            Util.setShort(buffer, (short) (offset + length), keyGenerator.getSW());
            length += 2;
        }

        return length;
    }

    /**
     * @param keyPair KeyPair to clear
     * @param buffer  buffer to write sw to
     * @param offset  offset into buffer
     * @return length of data written to the buffer
     */
    private short clear(KeyPair keyPair, byte[] buffer, short offset) {
        short sw = keyGenerator.clearPair(keyPair, EC_Consts.KEY_BOTH);
        Util.setShort(buffer, offset, sw);

        return 2;
    }

    /**
     * @param keyPair   KeyPair to set params on
     * @param curve     curve to set (EC_Consts.CURVE_*)
     * @param params    parameters to set (EC_Consts.PARAMETER_* | ...)
     * @param buffer    buffer to read params from and write sw to
     * @param inOffset  input offset in buffer
     * @param outOffset output offset in buffer
     * @return length of data written to the buffer
     */
    private short set(KeyPair keyPair, byte curve, short params, byte[] buffer, short inOffset, short outOffset) {
        short sw = ISO7816.SW_NO_ERROR;

        switch (curve) {
            case EC_Consts.CURVE_default:
                //default, dont set anything
                break;
            case EC_Consts.CURVE_external:
                //external
                sw = keyGenerator.setExternalCurve(keyPair, params, buffer, inOffset);
                break;
            default:
                //custom
                sw = keyGenerator.setCurve(keyPair, curve, params, ramArray, (short) 0);
                break;
        }

        Util.setShort(buffer, outOffset, sw);
        return 2;
    }

    /**
     * @param keyPair    KeyPair to corrupt
     * @param key        key to corrupt (EC_Consts.KEY_* | ...)
     * @param params     parameters to corrupt (EC_Consts.PARAMETER_* | ...)
     * @param corruption corruption type (EC_Consts.CORRUPTION_*)
     * @param buffer     buffer to output sw to
     * @param offset     output offset in buffer
     * @return length of data written to the buffer
     */
    private short corrupt(KeyPair keyPair, byte key, short params, byte corruption, byte[] buffer, short offset) {
        short sw = keyGenerator.corruptCurve(keyPair, key, params, corruption, ramArray, (short) 0);
        Util.setShort(buffer, offset, sw);
        return 2;
    }

    /**
     * @param keyPair KeyPair to generate
     * @param buffer  buffer to write sw to
     * @param offset  output offset in buffer
     * @return length of data written to the buffer
     */
    private short generate(KeyPair keyPair, byte[] buffer, short offset) {
        short sw = keyGenerator.generatePair(keyPair);
        Util.setShort(buffer, offset, sw);

        return 2;
    }

    /**
     * @param keyPair  KeyPair to export from
     * @param key      which key to export from (EC_Consts.KEY_PUBLIC | EC_Consts.KEY_PRIVATE)
     * @param params   which params to export (EC_Consts.PARAMETER_* | ...)
     * @param buffer   buffer to export params to
     * @param swOffset offset to output sw to buffer
     * @param offset   output offset in buffer
     * @return length of data written to the buffer
     */
    private short export(KeyPair keyPair, byte key, short params, byte[] buffer, short swOffset, short offset) {
        short length = 0;

        short sw = ISO7816.SW_NO_ERROR;
        if ((key & EC_Consts.KEY_PUBLIC) != 0) {
            //export params from public
            length += keyGenerator.exportParameters(keyPair, EC_Consts.KEY_PUBLIC, params, buffer, offset);
            sw = keyGenerator.getSW();
        }
        //TODO unify this, now that param key == the passed on param.
        if ((key & EC_Consts.KEY_PRIVATE) != 0 && sw == ISO7816.SW_NO_ERROR) {
            //export params from private
            length += keyGenerator.exportParameters(keyPair, EC_Consts.KEY_PRIVATE, params, buffer, (short) (offset + length));
            sw = keyGenerator.getSW();
        }
        Util.setShort(buffer, swOffset, sw);

        return length;
    }

    /**
     * @param pubkey     keyPair to use for public key, (KEYPAIR_LOCAL || KEYPAIR_REMOTE)
     * @param privkey    keyPair to use for private key, (KEYPAIR_LOCAL || KEYPAIR_REMOTE)
     * @param export     whether to export ECDH secret
     * @param corruption whether to invalidate the pubkey before ECDH
     * @param type
     * @param buffer     buffer to write sw to, and export ECDH secret {@code if(export == EXPORT_TRUE)}
     * @param offset     output offset in buffer
     * @return length of data written to the buffer
     */
    private short ecdh(byte pubkey, byte privkey, byte export, byte corruption, byte type, byte[] buffer, short offset) {
        short length = 0;

        KeyPair pub = ((pubkey & KEYPAIR_LOCAL) != 0) ? localKeypair : remoteKeypair;
        KeyPair priv = ((privkey & KEYPAIR_LOCAL) != 0) ? localKeypair : remoteKeypair;

        short secretLength = 0;
        switch (type) {
            case EC_Consts.KA_ECDH:
                secretLength = keyTester.testECDH((ECPrivateKey) priv.getPrivate(), (ECPublicKey) pub.getPublic(), ramArray, (short) 0, ramArray2, (short) 0, corruption);
                break;
            case EC_Consts.KA_ECDHC:
                secretLength = keyTester.testECDHC((ECPrivateKey) priv.getPrivate(), (ECPublicKey) pub.getPublic(), ramArray, (short) 0, ramArray2, (short) 0, corruption);
                break;
            case EC_Consts.KA_BOTH:
                // TODO
                break;
            default:
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        Util.setShort(buffer, offset, keyTester.getSW());
        length += 2;

        if ((export == EXPORT_TRUE)) {
            Util.setShort(buffer, (short) (offset + length), secretLength);
            length += 2;
            Util.arrayCopyNonAtomic(ramArray2, (short) 0, buffer, (short) (offset + length), secretLength);
            length += secretLength;
        }

        return length;
    }

    /**
     * @param sign      keyPair to use for signing and verification
     * @param export    whether to export ECDSA signature
     * @param buffer    buffer to write sw to, and export ECDSA signature {@code if(export == EXPORT_TRUE)}
     * @param inOffset  input offset in buffer
     * @param outOffset output offset in buffer
     * @return length of data written to the buffer
     */
    private short ecdsa(KeyPair sign, byte export, byte[] buffer, short inOffset, short outOffset) {
        short length = 0;

        short dataLength = Util.getShort(buffer, inOffset);
        if (dataLength == 0) { //no data to sign
            //generate random
            dataLength = 32;
            randomData.generateData(ramArray, (short) 0, dataLength);
        } else {
            Util.arrayCopyNonAtomic(buffer, (short) (inOffset + 2), ramArray, (short) 0, dataLength);
        }

        short signatureLength = keyTester.testECDSA((ECPrivateKey) sign.getPrivate(), (ECPublicKey) sign.getPublic(), ramArray, (short) 0, dataLength, ramArray2, (short) 0);
        Util.setShort(buffer, outOffset, keyTester.getSW());
        length += 2;

        if (export == EXPORT_TRUE) {
            Util.setShort(buffer, (short) (outOffset + length), signatureLength);
            length += 2;

            Util.arrayCopyNonAtomic(ramArray2, (short) 0, buffer, (short) (outOffset + length), signatureLength);
            length += signatureLength;
        }

        return length;
    }

    /**
     * @param buffer
     * @param offset
     * @return
     */
    private short cleanup(byte[] buffer, short offset) {
        short sw = ISO7816.SW_NO_ERROR;
        try {
            if (JCSystem.isObjectDeletionSupported())
                JCSystem.requestObjectDeletion();
        } catch (CardRuntimeException crex) {
            sw = crex.getReason();
        }

        Util.setShort(buffer, offset, sw);
        return 2;
    }

    /**
     *
     * @param buffer
     * @param offset
     * @return
     */
    private short support(byte[] buffer, short offset) {

        Util.setShort(buffer, offset, ecdhSW);
        Util.setShort(buffer, (short) (offset+2), ecdhcSW);
        Util.setShort(buffer, (short) (offset+4), ecdsaSW);

        return 6;
    }
}
