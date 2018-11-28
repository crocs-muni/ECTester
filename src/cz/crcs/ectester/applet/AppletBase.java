package cz.crcs.ectester.applet;

import javacard.framework.*;
import javacard.security.*;

public abstract class AppletBase extends Applet {

    // MAIN INSTRUCTION CLASS
    public static final byte CLA_ECTESTERAPPLET = (byte) 0xB0;

    // INSTRUCTIONS
    public static final byte INS_ALLOCATE = (byte) 0x5a;
    public static final byte INS_CLEAR = (byte) 0x5b;
    public static final byte INS_SET = (byte) 0x5c;
    public static final byte INS_TRANSFORM = (byte) 0x5d;
    public static final byte INS_GENERATE = (byte) 0x5e;
    public static final byte INS_EXPORT = (byte) 0x5f;
    public static final byte INS_ECDH = (byte) 0x70;
    public static final byte INS_ECDH_DIRECT = (byte) 0x71;
    public static final byte INS_ECDSA = (byte) 0x72;
    public static final byte INS_ECDSA_SIGN = (byte) 0x73;
    public static final byte INS_ECDSA_VERIFY = (byte) 0x74;
    public static final byte INS_CLEANUP = (byte) 0x75;
    public static final byte INS_ALLOCATE_KA = (byte) 0x76;
    public static final byte INS_ALLOCATE_SIG = (byte) 0x77;
    public static final byte INS_GET_INFO = (byte) 0x78;

    // PARAMETERS for P1 and P2
    public static final byte KEYPAIR_LOCAL = (byte) 0x01;
    public static final byte KEYPAIR_REMOTE = (byte) 0x02;
    public static final byte KEYPAIR_BOTH = KEYPAIR_LOCAL | KEYPAIR_REMOTE;
    public static final byte EXPORT_TRUE = (byte) 0xff;
    public static final byte EXPORT_FALSE = (byte) 0x00;

    // STATUS WORDS
    public static final short SW_SIG_VERIFY_FAIL = (short) 0x0ee1;
    public static final short SW_DH_DHC_MISMATCH = (short) 0x0ee2;
    public static final short SW_KEYPAIR_NULL = (short) 0x0ee3;
    public static final short SW_KA_NULL = (short) 0x0ee4;
    public static final short SW_SIGNATURE_NULL = (short) 0x0ee5;
    public static final short SW_OBJECT_NULL = (short) 0x0ee6;
    public static final short SW_Exception = (short) 0xff01;
    public static final short SW_ArrayIndexOutOfBoundsException = (short) 0xff02;
    public static final short SW_ArithmeticException = (short) 0xff03;
    public static final short SW_ArrayStoreException = (short) 0xff04;
    public static final short SW_NullPointerException = (short) 0xff05;
    public static final short SW_NegativeArraySizeException = (short) 0xff06;
    public static final short SW_CryptoException_prefix = (short) 0xf100;
    public static final short SW_SystemException_prefix = (short) 0xf200;
    public static final short SW_PINException_prefix = (short) 0xf300;
    public static final short SW_TransactionException_prefix = (short) 0xf400;
    public static final short SW_CardRuntimeException_prefix = (short) 0xf500;

    //
    public static final short BASE_221 = (short) 0x0221;
    public static final short BASE_222 = (short) 0x0222;

    //
    public static final byte[] VERSION = {'v', '0', '.', '3', '.', '0'};

    public static final short ARRAY_LENGTH = 0x100;
    public static final short APDU_MAX_LENGTH = 1024;

    // TEMPORARRY ARRAY IN RAM
    byte[] ramArray = null;
    byte[] ramArray2 = null;
    byte[] apduArray = null;

    RandomData randomData = null;

    ECKeyTester keyTester = null;
    ECKeyGenerator keyGenerator = null;
    KeyPair localKeypair = null;
    KeyPair remoteKeypair = null;

    protected AppletBase(byte[] buffer, short offset, byte length) {
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
            apduArray = JCSystem.makeTransientByteArray(APDU_MAX_LENGTH, JCSystem.CLEAR_ON_RESET);

            randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
            EC_Consts.randomData = randomData;

            keyGenerator = new ECKeyGenerator();
            keyTester = new ECKeyTester();
        }
    }

    public void process(APDU apdu) throws ISOException {
        // get the APDU buffer
        byte[] apduBuffer = apdu.getBuffer();
        byte cla = apduBuffer[ISO7816.OFFSET_CLA];
        byte ins = apduBuffer[ISO7816.OFFSET_INS];

        // ignore the applet select command dispatched to the process
        if (selectingApplet()) {
            return;
        }

        if (cla == CLA_ECTESTERAPPLET) {
            try {
                readAPDU(apdu, apduArray, APDU_MAX_LENGTH);

                short length = 0;
                switch (ins) {
                    case INS_ALLOCATE_KA:
                        length = insAllocateKA(apdu);
                        break;
                    case INS_ALLOCATE_SIG:
                        length = insAllocateSig(apdu);
                        break;
                    case INS_ALLOCATE:
                        length = insAllocate(apdu);
                        break;
                    case INS_CLEAR:
                        length = insClear(apdu);
                        break;
                    case INS_SET:
                        length = insSet(apdu);
                        break;
                    case INS_TRANSFORM:
                        length = insTransform(apdu);
                        break;
                    case INS_GENERATE:
                        length = insGenerate(apdu);
                        break;
                    case INS_EXPORT:
                        length = insExport(apdu);
                        break;
                    case INS_ECDH:
                        length = insECDH(apdu);
                        break;
                    case INS_ECDH_DIRECT:
                        length = insECDH_direct(apdu);
                        break;
                    case INS_ECDSA:
                        length = insECDSA(apdu);
                        break;
                    case INS_ECDSA_SIGN:
                        length = insECDSA_sign(apdu);
                        break;
                    case INS_ECDSA_VERIFY:
                        length = insECDSA_verify(apdu);
                        break;
                    case INS_CLEANUP:
                        length = insCleanup(apdu);
                        break;
                    case INS_GET_INFO:
                        length = insGetInfo(apdu);
                        break;
                    default:
                        // The INS code is not supported by the dispatcher
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                        break;
                }
                apdu.setOutgoingAndSend((short) 0, length);

            } catch (ISOException e) {
                throw e; // Our exception from code, just re-emit
            } catch (ArrayIndexOutOfBoundsException e) {
                ISOException.throwIt(SW_ArrayIndexOutOfBoundsException);
            } catch (ArithmeticException e) {
                ISOException.throwIt(SW_ArithmeticException);
            } catch (ArrayStoreException e) {
                ISOException.throwIt(SW_ArrayStoreException);
            } catch (NullPointerException e) {
                ISOException.throwIt(SW_NullPointerException);
            } catch (NegativeArraySizeException e) {
                ISOException.throwIt(SW_NegativeArraySizeException);
            } catch (CryptoException e) {
                ISOException.throwIt((short) (SW_CryptoException_prefix | e.getReason()));
            } catch (SystemException e) {
                ISOException.throwIt((short) (SW_SystemException_prefix | e.getReason()));
            } catch (PINException e) {
                ISOException.throwIt((short) (SW_PINException_prefix | e.getReason()));
            } catch (TransactionException e) {
                ISOException.throwIt((short) (SW_TransactionException_prefix | e.getReason()));
            } catch (CardRuntimeException e) {
                ISOException.throwIt((short) (SW_CardRuntimeException_prefix | e.getReason()));
            } catch (Exception e) {
                ISOException.throwIt(SW_Exception);
            }

        } else ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }

    private void readAPDU(APDU apdu, byte[] buffer, short length) {
        short read = apdu.setIncomingAndReceive();
        read += getOffsetCdata(apdu);
        short total = getIncomingLength(apdu);
        if (total > length) {
            return;
        }

        byte[] apduBuffer = apdu.getBuffer();
        short sum = 0;

        do {
            Util.arrayCopyNonAtomic(apduBuffer, (short) 0, buffer, sum, read);
            sum += read;
            read = apdu.receiveBytes((short) 0);
        } while (sum < total);
    }

    abstract short getOffsetCdata(APDU apdu);

    abstract short getIncomingLength(APDU apdu);

    abstract short getBase();

    /**
     * Allocates KeyAgreement object, returns allocate SW.
     *
     * @param apdu DATA = byte KeyAgreementType
     * @return length of response
     */
    private short insAllocateKA(APDU apdu) {
        short cdata = getOffsetCdata(apdu);
        byte kaType = apduArray[cdata];
        short sw = keyTester.allocateKA(kaType);
        Util.setShort(apdu.getBuffer(), (short) 0, sw);
        return 2;
    }

    /**
     * Allocates a Signature object, returns allocate SW.
     *
     * @param apdu DATA = byte SignatureType
     * @return length of response
     */
    private short insAllocateSig(APDU apdu) {
        short cdata = getOffsetCdata(apdu);
        byte sigType = apduArray[cdata];
        short sw = keyTester.allocateSig(sigType);
        Util.setShort(apdu.getBuffer(), (short) 0, sw);
        return 2;
    }

    /**
     * Allocates local and remote keyPairs.
     * returns allocate SWs
     *
     * @param apdu P1   = byte keyPair (KEYPAIR_* | ...)
     *             P2   =
     *             DATA = short keyLength
     *             byte keyClass
     * @return length of response
     */
    private short insAllocate(APDU apdu) {
        byte keyPair = apduArray[ISO7816.OFFSET_P1];
        short cdata = getOffsetCdata(apdu);
        short keyLength = Util.getShort(apduArray, cdata);
        byte keyClass = apduArray[(short) (cdata + 2)];

        return allocate(keyPair, keyLength, keyClass, apdu.getBuffer(), (short) 0);
    }

    /**
     * Clears local and remote keyPair's keys {@code .clearKey()}.
     * returns clearKey SWs
     *
     * @param apdu P1   = byte keyPair (KEYPAIR_* | ...)
     *             P2   =
     * @return length of response
     */
    private short insClear(APDU apdu) {
        byte keyPair = apduArray[ISO7816.OFFSET_P1];

        short len = 0;
        if ((keyPair & KEYPAIR_LOCAL) != 0) {
            len += clear(localKeypair, apdu.getBuffer(), (short) 0);
        }
        if ((keyPair & KEYPAIR_REMOTE) != 0) {
            len += clear(remoteKeypair, apdu.getBuffer(), len);
        }

        return len;
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
     * @return length of response
     */
    private short insSet(APDU apdu) {
        byte keyPair = apduArray[ISO7816.OFFSET_P1];
        byte curve = apduArray[ISO7816.OFFSET_P2];
        short cdata = getOffsetCdata(apdu);
        short params = Util.getShort(apduArray, cdata);

        short len = 0;

        if ((keyPair & KEYPAIR_LOCAL) != 0) {
            len += set(localKeypair, curve, params, apduArray, (short) (cdata + 2), apdu.getBuffer(), (short) 0);
        }
        if ((keyPair & KEYPAIR_REMOTE) != 0) {
            len += set(remoteKeypair, curve, params, apduArray, (short) (cdata + 2), apdu.getBuffer(), len);
        }

        return len;
    }

    /**
     * Transforms curve paramaters of local and remote keyPairs.
     * returns transformCurve SWs
     *
     * @param apdu P1 = byte keyPair (KEYPAIR_* | ...)
     *             P2 = byte key (EC_Consts.KEY_* | ...)
     *             DATA = short params (EC_Consts.PARAMETER_* | ...)
     *             short transformation (EC_Consts.TRANSFORMATION_* || ...)
     * @return length of response
     */
    private short insTransform(APDU apdu) {
        byte keyPair = apduArray[ISO7816.OFFSET_P1];
        byte key = apduArray[ISO7816.OFFSET_P2];
        short cdata = getOffsetCdata(apdu);
        short params = Util.getShort(apduArray, cdata);
        short transformation = Util.getShort(apduArray, (short) (cdata + 2));

        short len = 0;
        if ((keyPair & KEYPAIR_LOCAL) != 0) {
            len += transform(localKeypair, key, params, transformation, apdu.getBuffer(), (short) 0);
        }

        if ((keyPair & KEYPAIR_REMOTE) != 0) {
            len += transform(remoteKeypair, key, params, transformation, apdu.getBuffer(), len);
        }

        return len;
    }

    /**
     * Generates the local and remote keyPairs.
     * returns generate SWs
     *
     * @param apdu P1   = byte keyPair (KEYPAIR_* | ...)
     *             P2   =
     * @return length of response
     */
    private short insGenerate(APDU apdu) {
        byte keyPair = apduArray[ISO7816.OFFSET_P1];

        short len = 0;
        if ((keyPair & KEYPAIR_LOCAL) != 0) {
            len += generate(localKeypair, apdu.getBuffer(), (short) 0);
        }
        if ((keyPair & KEYPAIR_REMOTE) != 0) {
            len += generate(remoteKeypair, apdu.getBuffer(), len);
        }

        return len;
    }

    /**
     * Exports selected key and domain parameters from the selected keyPair and key.
     *
     * @param apdu P1   = byte keyPair (KEYPAIR_* | ...)
     *             P2   = byte key (EC_Consts.KEY_* | ...)
     *             DATA = short params
     * @return length of response
     */
    private short insExport(APDU apdu) {
        byte keyPair = apduArray[ISO7816.OFFSET_P1];
        byte key = apduArray[ISO7816.OFFSET_P2];
        short cdata = getOffsetCdata(apdu);
        short params = Util.getShort(apduArray, cdata);

        short swOffset = 0;
        short len = (short) (keyPair == KEYPAIR_BOTH ? 4 : 2);

        if ((keyPair & KEYPAIR_LOCAL) != 0) {
            len += export(localKeypair, key, params, apdu.getBuffer(), swOffset, len);
            swOffset += 2;
        }
        if ((keyPair & KEYPAIR_REMOTE) != 0) {
            len += export(remoteKeypair, key, params, apdu.getBuffer(), swOffset, len);
        }

        return len;
    }

    /**
     * Performs ECDH, between the pubkey specified in P1(local/remote) and the privkey specified in P2(local/remote).
     * returns deriveSecret SW, {@code if(export == EXPORT_TRUE)} => short secretlen, byte[] secret
     *
     * @param apdu P1   = byte pubkey (KEYPAIR_*)
     *             P2   = byte privkey (KEYPAIR_*)
     *             DATA = byte export (EXPORT_TRUE || EXPORT_FALSE)
     *             short transformation (EC_Consts.TRANSFORMATION_* | ...)
     *             byte type (EC_Consts.KA_* | ...)
     * @return length of response
     */
    private short insECDH(APDU apdu) {
        byte pubkey = apduArray[ISO7816.OFFSET_P1];
        byte privkey = apduArray[ISO7816.OFFSET_P2];
        short cdata = getOffsetCdata(apdu);
        byte export = apduArray[cdata];
        short transformation = Util.getShort(apduArray, (short) (cdata + 1));
        byte type = apduArray[(short) (cdata + 3)];

        return ecdh(pubkey, privkey, export, transformation, type, apdu.getBuffer(), (short) 0);
    }

    /**
     * Performs ECDH, directly between the privkey specified in P1(local/remote) and the raw data
     *
     * @param apdu P1   = byte privkey (KEYPAIR_*)
     *             P2   = byte export (EXPORT_TRUE || EXPORT_FALSE)
     *             DATA = short transformation (EC_Consts.TRANSFORMATION_* | ...)
     *             byte type (EC_Consts.KA_* | ...)
     *             short length
     *             byte[] pubkey
     * @return length of response
     */
    private short insECDH_direct(APDU apdu) {
        byte privkey = apduArray[ISO7816.OFFSET_P1];
        byte export = apduArray[ISO7816.OFFSET_P2];
        short cdata = getOffsetCdata(apdu);
        short transformation = Util.getShort(apduArray, cdata);
        byte type = apduArray[(short) (cdata + 2)];
        short length = Util.getShort(apduArray, (short) (cdata + 3));

        return ecdh_direct(privkey, export, transformation, type, (short) (cdata + 5), length, apdu.getBuffer(), (short) 0);
    }

    /**
     * Performs ECDSA signature and verification on data provided or random, using the keyPair in P1(local/remote).
     * returns ecdsa SW, {@code if(export == EXPORT_TRUE)} => short signature_length, byte[] signature
     *
     * @param apdu P1   = byte keyPair (KEYPAIR_*)
     *             P2   = byte export (EXPORT_TRUE || EXPORT_FALSE)
     *             DATA = byte sigType
     *             short dataLength (00 = random data generated, !00 = data length)
     *             byte[] data
     * @return length of response
     */
    private short insECDSA(APDU apdu) {
        byte keyPair = apduArray[ISO7816.OFFSET_P1];
        byte export = apduArray[ISO7816.OFFSET_P2];
        short cdata = getOffsetCdata(apdu);
        byte sigType = apduArray[cdata];

        short len = 0;
        if ((keyPair & KEYPAIR_LOCAL) != 0) {
            len += ecdsa(localKeypair, sigType, export, apduArray, (short) (cdata + 1), apdu.getBuffer(), (short) 0);
        }
        if ((keyPair & KEYPAIR_REMOTE) != 0) {
            len += ecdsa(remoteKeypair, sigType, export, apduArray, (short) (cdata + 1), apdu.getBuffer(), len);
        }

        return len;
    }

    /**
     * @param apdu P1   = byte keyPair (KEYPAIR_*)
     *             P2   = byte export (EXPORT_TRUE || EXPORT_FALSE)
     *             DATA = byte sigType
     *             short dataLength (00 = random data generated, !00 = data length)
     *             byte[] data
     * @return length of response
     */
    private short insECDSA_sign(APDU apdu) {
        byte keyPair = apduArray[ISO7816.OFFSET_P1];
        byte export = apduArray[ISO7816.OFFSET_P2];
        short cdata = getOffsetCdata(apdu);
        byte sigType = apduArray[cdata];

        short len = 0;
        if ((keyPair & KEYPAIR_LOCAL) != 0) {
            len += ecdsa_sign(localKeypair, sigType, export, apduArray, (short) (cdata + 1), apdu.getBuffer(), (short) 0);
        }
        if ((keyPair & KEYPAIR_REMOTE) != 0) {
            len += ecdsa_sign(remoteKeypair, sigType, export, apduArray, (short) (cdata + 1), apdu.getBuffer(), len);
        }
        return len;
    }

    /**
     * @param apdu P1   = byte keyPair (KEYPAIR_*)
     *             P2   = byte sigType
     *             DATA = short dataLength (00 = random data generated, !00 = data length)
     *             byte[] data
     *             short sigLength
     *             byte[] signature
     * @return length of response
     */
    private short insECDSA_verify(APDU apdu) {
        byte keyPair = apduArray[ISO7816.OFFSET_P1];
        byte sigType = apduArray[ISO7816.OFFSET_P2];
        short cdata = getOffsetCdata(apdu);

        short len = 0;
        if ((keyPair & KEYPAIR_LOCAL) != 0) {
            len += ecdsa_verify(localKeypair, sigType, apduArray, cdata, apdu.getBuffer(), (short) 0);
        }
        if ((keyPair & KEYPAIR_REMOTE) != 0) {
            len += ecdsa_verify(remoteKeypair, sigType, apduArray, cdata, apdu.getBuffer(), len);
        }
        return len;
    }


    /**
     * Performs card memory cleanup via JCSystem.requestObjectDeletion()
     *
     * @param apdu no data
     * @return length of response
     */
    private short insCleanup(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();

        return cleanup(apdubuf, (short) 0);
    }

    /**
     * Gathers info about the applet and the card environment.
     *
     * @param apdu no data
     * @return length of response
     */
    private short insGetInfo(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();

        return getInfo(apdubuf, (short) 0);
    }

    /**
     * @param keyPair   which keyPair to use, local/remote (KEYPAIR_* | ...)
     * @param keyLength key length to set
     * @param keyClass  key class to allocate
     * @param outBuffer buffer to write sw to
     * @param outOffset offset into buffer
     * @return length of data written to the buffer
     */
    private short allocate(byte keyPair, short keyLength, byte keyClass, byte[] outBuffer, short outOffset) {
        short length = 0;
        if ((keyPair & KEYPAIR_LOCAL) != 0) {
            localKeypair = keyGenerator.allocatePair(keyClass, keyLength);
            Util.setShort(outBuffer, outOffset, keyGenerator.getSW());
            length += 2;
        }

        if ((keyPair & KEYPAIR_REMOTE) != 0) {
            remoteKeypair = keyGenerator.allocatePair(keyClass, keyLength);
            Util.setShort(outBuffer, (short) (outOffset + length), keyGenerator.getSW());
            length += 2;
        }

        return length;
    }

    /**
     * @param keyPair   KeyPair to clear
     * @param outBuffer buffer to write sw to
     * @param outOffset offset into buffer
     * @return length of data written to the buffer
     */
    private short clear(KeyPair keyPair, byte[] outBuffer, short outOffset) {
        short sw = keyGenerator.clearPair(keyPair, EC_Consts.KEY_BOTH);
        Util.setShort(outBuffer, outOffset, sw);

        return 2;
    }

    /**
     * @param keyPair   KeyPair to set params on
     * @param curve     curve to set (EC_Consts.CURVE_*)
     * @param params    parameters to set (EC_Consts.PARAMETER_* | ...)
     * @param inBuffer  buffer to read params from
     * @param inOffset  input offset in buffer
     * @param outBuffer buffer to write sw to
     * @param outOffset output offset in buffer
     * @return length of data written to the buffer
     */
    private short set(KeyPair keyPair, byte curve, short params, byte[] inBuffer, short inOffset, byte[] outBuffer, short outOffset) {
        short sw = ISO7816.SW_NO_ERROR;

        switch (curve) {
            case EC_Consts.CURVE_default:
                //default, dont set anything
                break;
            case EC_Consts.CURVE_external:
                //external
                sw = keyGenerator.setExternalCurve(keyPair, params, inBuffer, inOffset);
                break;
            default:
                //custom
                sw = keyGenerator.setCurve(keyPair, curve, params, ramArray, (short) 0);
                break;
        }

        Util.setShort(outBuffer, outOffset, sw);
        return 2;
    }

    /**
     * @param keyPair        KeyPair to transform
     * @param key            key to transform (EC_Consts.KEY_* | ...)
     * @param params         parameters to transform (EC_Consts.PARAMETER_* | ...)
     * @param transformation transformation type (EC_Consts.TRANSFORMATION_*)
     * @param outBuffer      buffer to output sw to
     * @param outOffset      output offset in buffer
     * @return length of data written to the buffer
     */
    private short transform(KeyPair keyPair, byte key, short params, short transformation, byte[] outBuffer, short outOffset) {
        short sw = keyGenerator.transformCurve(keyPair, key, params, transformation, ramArray, (short) 0);
        Util.setShort(outBuffer, outOffset, sw);
        return 2;
    }

    /**
     * @param keyPair   KeyPair to generate
     * @param outBuffer buffer to output sw to
     * @param outOffset output offset in buffer
     * @return length of data written to the buffer
     */
    private short generate(KeyPair keyPair, byte[] outBuffer, short outOffset) {
        short sw = keyGenerator.generatePair(keyPair);
        Util.setShort(outBuffer, outOffset, sw);

        return 2;
    }

    /**
     * @param keyPair   KeyPair to export from
     * @param key       which key to export from (EC_Consts.KEY_PUBLIC | EC_Consts.KEY_PRIVATE)
     * @param params    which params to export (EC_Consts.PARAMETER_* | ...)
     * @param outBuffer buffer to export params to
     * @param swOffset  offset to output sw to buffer
     * @param outOffset output offset in buffer
     * @return length of data written to the buffer
     */
    private short export(KeyPair keyPair, byte key, short params, byte[] outBuffer, short swOffset, short outOffset) {
        short length = 0;

        short sw = ISO7816.SW_NO_ERROR;
        if ((key & EC_Consts.KEY_PUBLIC) != 0) {
            //export params from public
            length += keyGenerator.exportParameters(keyPair, EC_Consts.KEY_PUBLIC, params, outBuffer, outOffset);
            sw = keyGenerator.getSW();
        }
        if ((key & EC_Consts.KEY_PRIVATE) != 0 && sw == ISO7816.SW_NO_ERROR) {
            //export params from private
            length += keyGenerator.exportParameters(keyPair, EC_Consts.KEY_PRIVATE, params, outBuffer, (short) (outOffset + length));
            sw = keyGenerator.getSW();
        }
        Util.setShort(outBuffer, swOffset, sw);

        return length;
    }

    /**
     * @param pubkey         keyPair to use for public key, (KEYPAIR_LOCAL || KEYPAIR_REMOTE)
     * @param privkey        keyPair to use for private key, (KEYPAIR_LOCAL || KEYPAIR_REMOTE)
     * @param export         whether to export ECDH secret
     * @param transformation whether to transform the pubkey before ECDH
     * @param type           KeyAgreement type to test
     * @param outBuffer      buffer to write sw to, and export ECDH secret {@code if(export == EXPORT_TRUE)}
     * @param outOffset      output offset in buffer
     * @return length of data written to the buffer
     */
    private short ecdh(byte pubkey, byte privkey, byte export, short transformation, byte type, byte[] outBuffer, short outOffset) {
        short length = 0;

        KeyPair pub = ((pubkey & KEYPAIR_LOCAL) != 0) ? localKeypair : remoteKeypair;
        KeyPair priv = ((privkey & KEYPAIR_LOCAL) != 0) ? localKeypair : remoteKeypair;

        short secretLength = 0;
        if (keyTester.getKaType() == type) {
            secretLength = keyTester.testKA(priv, pub, ramArray, (short) 0, ramArray2, (short) 0, transformation);
        } else {
            short allocateSW = keyTester.allocateKA(type);
            if (allocateSW == ISO7816.SW_NO_ERROR) {
                secretLength = keyTester.testKA(priv, pub, ramArray, (short) 0, ramArray2, (short) 0, transformation);
            }
        }
        Util.setShort(outBuffer, outOffset, keyTester.getSW());
        length += 2;

        if ((export == EXPORT_TRUE)) {
            Util.setShort(outBuffer, (short) (outOffset + length), secretLength);
            length += 2;
            Util.arrayCopyNonAtomic(ramArray2, (short) 0, outBuffer, (short) (outOffset + length), secretLength);
            length += secretLength;
        }

        return length;
    }

    private short ecdh_direct(byte privkey, byte export, short transformation, byte type, short keyOffset, short keyLength, byte[] outBuffer, short outOffset) {
        short length = 0;

        KeyPair priv = ((privkey & KEYPAIR_LOCAL) != 0) ? localKeypair : remoteKeypair;

        short secretLength = 0;
        if (keyTester.getKaType() == type) {
            secretLength = keyTester.testKA_direct(priv, apduArray, keyOffset, keyLength, ramArray2, (short) 0, transformation);
        } else {
            short allocateSW = keyTester.allocateKA(type);
            if (allocateSW == ISO7816.SW_NO_ERROR) {
                secretLength = keyTester.testKA_direct(priv, apduArray, keyOffset, keyLength, ramArray2, (short) 0, transformation);
            }
        }

        Util.setShort(outBuffer, outOffset, keyTester.getSW());
        length += 2;

        if ((export == EXPORT_TRUE)) {
            Util.setShort(outBuffer, (short) (outOffset + length), secretLength);
            length += 2;
            Util.arrayCopyNonAtomic(ramArray2, (short) 0, outBuffer, (short) (outOffset + length), secretLength);
            length += secretLength;
        }
        return length;
    }

    /**
     * @param sign      keyPair to use for signing and verification
     * @param sigType   Signature type to use
     * @param export    whether to export ECDSA signature
     * @param inBuffer  buffer to read dataLength and data to sign from
     * @param inOffset  input offset in buffer
     * @param outBuffer buffer to write sw to, and export ECDSA signature {@code if(export == EXPORT_TRUE)}
     * @param outOffset output offset in buffer
     * @return length of data written to the buffer
     */
    private short ecdsa(KeyPair sign, byte sigType, byte export, byte[] inBuffer, short inOffset, byte[] outBuffer, short outOffset) {
        short length = 0;

        short dataLength = Util.getShort(inBuffer, inOffset);
        if (dataLength == 0) { //no data to sign
            //generate random
            dataLength = 64;
            randomData.generateData(ramArray, (short) 0, dataLength);
        } else {
            Util.arrayCopyNonAtomic(inBuffer, (short) (inOffset + 2), ramArray, (short) 0, dataLength);
        }

        short signatureLength = 0;
        if (keyTester.getSigType() == sigType) {
            signatureLength = keyTester.testECDSA((ECPrivateKey) sign.getPrivate(), (ECPublicKey) sign.getPublic(), ramArray, (short) 0, dataLength, ramArray2, (short) 0);
        } else {
            short allocateSW = keyTester.allocateSig(sigType);
            if (allocateSW == ISO7816.SW_NO_ERROR) {
                signatureLength = keyTester.testECDSA((ECPrivateKey) sign.getPrivate(), (ECPublicKey) sign.getPublic(), ramArray, (short) 0, dataLength, ramArray2, (short) 0);
            }
        }
        Util.setShort(outBuffer, outOffset, keyTester.getSW());
        length += 2;

        if (export == EXPORT_TRUE) {
            Util.setShort(outBuffer, (short) (outOffset + length), signatureLength);
            length += 2;

            Util.arrayCopyNonAtomic(ramArray2, (short) 0, outBuffer, (short) (outOffset + length), signatureLength);
            length += signatureLength;
        }

        return length;
    }

    private short ecdsa_sign(KeyPair sign, byte sigType, byte export, byte[] inBuffer, short inOffset, byte[] outBuffer, short outOffset) {
        short length = 0;

        short dataLength = Util.getShort(inBuffer, inOffset);
        if (dataLength == 0) { //no data to sign
            //generate random
            dataLength = 64;
            randomData.generateData(ramArray, (short) 0, dataLength);
        } else {
            Util.arrayCopyNonAtomic(inBuffer, (short) (inOffset + 2), ramArray, (short) 0, dataLength);
        }

        short signatureLength = 0;
        if (keyTester.getSigType() == sigType) {
            signatureLength = keyTester.testECDSA_sign((ECPrivateKey) sign.getPrivate(), ramArray, (short) 0, dataLength, ramArray2, (short) 0);
        } else {
            short allocateSW = keyTester.allocateSig(sigType);
            if (allocateSW == ISO7816.SW_NO_ERROR) {
                signatureLength = keyTester.testECDSA_sign((ECPrivateKey) sign.getPrivate(), ramArray, (short) 0, dataLength, ramArray2, (short) 0);
            }
        }
        Util.setShort(outBuffer, outOffset, keyTester.getSW());
        length += 2;

        if (export == EXPORT_TRUE) {
            Util.setShort(outBuffer, (short) (outOffset + length), signatureLength);
            length += 2;

            Util.arrayCopyNonAtomic(ramArray2, (short) 0, outBuffer, (short) (outOffset + length), signatureLength);
            length += signatureLength;
        }

        return length;
    }

    private short ecdsa_verify(KeyPair verify, byte sigType, byte[] inBuffer, short inOffset, byte[] outBuffer, short outOffset) {
        short length = 0;

        short dataLength = Util.getShort(inBuffer, inOffset);
        short dataOffset = (short) (inOffset + 2);
        short sigLength = Util.getShort(inBuffer, (short) (dataOffset + dataLength));
        short sigOffset = (short) (dataOffset + dataLength + 2);

        if (keyTester.getSigType() == sigType) {
            keyTester.testECDSA_verify((ECPublicKey) verify.getPublic(), inBuffer, dataOffset, dataLength, inBuffer, sigOffset, sigLength);
        } else {
            short allocateSW = keyTester.allocateSig(sigType);
            if (allocateSW == ISO7816.SW_NO_ERROR) {
                keyTester.testECDSA_verify((ECPublicKey) verify.getPublic(), inBuffer, dataOffset, dataLength, inBuffer, sigOffset, sigLength);
            }
        }
        Util.setShort(outBuffer, outOffset, keyTester.getSW());
        length += 2;

        return length;
    }

    /**
     * @param buffer buffer to write sw to
     * @param offset output offset in buffer
     * @return length of data written to the buffer
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
     * @param buffer buffer to write sw to
     * @param offset output offset in buffer
     * @return length of data written to the buffer
     */
    private short getInfo(byte[] buffer, short offset) {
        short length = 0;
        Util.setShort(buffer, (short) (offset + length), ISO7816.SW_NO_ERROR);
        length += 2;
        Util.setShort(buffer, (short) (offset + length), (short) VERSION.length);
        length += 2;
        Util.arrayCopyNonAtomic(VERSION, (short) 0, buffer, (short) (offset + length), (short) (VERSION.length));
        length += VERSION.length;
        Util.setShort(buffer, (short) (offset + length), getBase());
        length += 2;
        Util.setShort(buffer, (short) (offset + length), JCSystem.getVersion());
        length += 2;
        Util.setShort(buffer, (short) (offset + length), (short) (JCSystem.isObjectDeletionSupported() ? 1 : 0));
        length += 2;
        Util.setShort(buffer, (short) (offset + length), (short) buffer.length);
        length += 2;
        Util.setShort(buffer, (short) (offset + length), (short) ramArray.length);
        length += 2;
        Util.setShort(buffer, (short) (offset + length), (short) ramArray2.length);
        length += 2;
        Util.setShort(buffer, (short) (offset + length), (short) apduArray.length);
        length += 2;
        return length;
    }
}
