package cz.crcs.ectester.applet;

public class CardConsts {
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
    public static final byte INS_SET_DRY_RUN_MODE = (byte) 0x79;
    public static final byte INS_BUFFER = (byte) 0x7a;
    public static final byte INS_PERFORM = (byte) 0x7b;

    // PARAMETERS for P1 and P2
    public static final byte KEYPAIR_LOCAL = (byte) 0x01;
    public static final byte KEYPAIR_REMOTE = (byte) 0x02;
    public static final byte KEYPAIR_BOTH = KEYPAIR_LOCAL | KEYPAIR_REMOTE;
    public static final byte BUILD_KEYPAIR = (byte) 0x01;
    public static final byte BUILD_KEYBUILDER = (byte) 0x02;
    public static final byte EXPORT_TRUE = (byte) 0xff;
    public static final byte EXPORT_FALSE = (byte) 0x00;
    public static final byte MODE_NORMAL = (byte) 0xaa;
    public static final byte MODE_DRY_RUN = (byte) 0xbb;

    // STATUS WORDS
    public static final short SW_SIG_VERIFY_FAIL = (short) 0x0ee1;
    public static final short SW_DH_DHC_MISMATCH = (short) 0x0ee2;
    public static final short SW_KEYPAIR_NULL = (short) 0x0ee3;
    public static final short SW_KA_NULL = (short) 0x0ee4;
    public static final short SW_SIGNATURE_NULL = (short) 0x0ee5;
    public static final short SW_OBJECT_NULL = (short) 0x0ee6;
    public static final short SW_CANNOT_FIT = (short) 0x0ee7;
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
    public static final short CDATA_BASIC = (short) 5;
    public static final short CDATA_EXTENDED = (short) 7;
}
