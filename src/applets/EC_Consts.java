package applets;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.KeyPair;
import javacard.security.RandomData;

public class EC_Consts {

    private static byte[] EC_FP_P = null;    //p
    private static byte[] EC_A = null;    //a
    private static byte[] EC_B = null;    //b
    private static byte[] EC_G_X = null;  //G[x,y]
    private static byte[] EC_G_Y = null;  //
    private static byte[] EC_R = null;    //n
    private static short EC_K = 1;        //h

    private static byte[] EC_W_X = null;    //Pubkey[x,y]
    private static byte[] EC_W_Y = null;
    private static byte[] EC_S = null;    //Private

    private static byte[] EC_F2M_F2M = null; //[short i1, short i2, short i3], f = x^m + x^i1 + x^i2 + x^i3 + 1

    public static final short PARAMETER_FP = 0x0001;
    public static final short PARAMETER_F2M = 0x0002;

    public static final short PARAMETER_A = 0x0004;
    public static final short PARAMETER_B = 0x0008;
    public static final short PARAMETER_G = 0x0010;
    public static final short PARAMETER_R = 0x0020;
    public static final short PARAMETER_K = 0x0040;
    public static final short PARAMETER_S = 0x0080;
    public static final short PARAMETER_W = 0x0100;

    public static RandomData m_random = null;

    public static final byte TAG_ECPUBKEY = (byte) 0x41;
    public static final byte TAG_ECPRIVKEY = (byte) 0x42;


    // secp128r1 
    public static final byte[] EC128_FP_P = new byte[]{
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFD,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};

    public static final byte[] EC128_FP_A = new byte[]{
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFD,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC};

    public static final byte[] EC128_FP_B = new byte[]{
            (byte) 0xE8, (byte) 0x75, (byte) 0x79, (byte) 0xC1,
            (byte) 0x10, (byte) 0x79, (byte) 0xF4, (byte) 0x3D,
            (byte) 0xD8, (byte) 0x24, (byte) 0x99, (byte) 0x3C,
            (byte) 0x2C, (byte) 0xEE, (byte) 0x5E, (byte) 0xD3};

    // G in compressed form / first part of ucompressed
    public static final byte[] EC128_FP_G_X = new byte[]{
            (byte) 0x16, (byte) 0x1F, (byte) 0xF7, (byte) 0x52,
            (byte) 0x8B, (byte) 0x89, (byte) 0x9B, (byte) 0x2D,
            (byte) 0x0C, (byte) 0x28, (byte) 0x60, (byte) 0x7C,
            (byte) 0xA5, (byte) 0x2C, (byte) 0x5B, (byte) 0x86};

    // second part of G uncompressed
    public static final byte[] EC128_FP_G_Y = new byte[]{
            (byte) 0xCF, (byte) 0x5A, (byte) 0xC8, (byte) 0x39,
            (byte) 0x5B, (byte) 0xAF, (byte) 0xEB, (byte) 0x13,
            (byte) 0xC0, (byte) 0x2D, (byte) 0xA2, (byte) 0x92,
            (byte) 0xDD, (byte) 0xED, (byte) 0x7A, (byte) 0x83};
    // Order of G
    public static final byte[] EC128_FP_R = new byte[]{
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x75, (byte) 0xA3, (byte) 0x0D, (byte) 0x1B,
            (byte) 0x90, (byte) 0x38, (byte) 0xA1, (byte) 0x15};
    // cofactor of G
    public static final short EC128_FP_K = 1;

    // secp160r1
    public static final byte[] EC160_FP_P = new byte[]{
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};

    public static final byte[] EC160_FP_A = new byte[]{
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC};

    public static final byte[] EC160_FP_B = new byte[]{
            (byte) 0x1C, (byte) 0x97, (byte) 0xBE, (byte) 0xFC,
            (byte) 0x54, (byte) 0xBD, (byte) 0x7A, (byte) 0x8B,
            (byte) 0x65, (byte) 0xAC, (byte) 0xF8, (byte) 0x9F,
            (byte) 0x81, (byte) 0xD4, (byte) 0xD4, (byte) 0xAD,
            (byte) 0xC5, (byte) 0x65, (byte) 0xFA, (byte) 0x45};

    // G in compressed form / first part of ucompressed
    public static final byte[] EC160_FP_G_X = new byte[]{
            (byte) 0x4A, (byte) 0x96, (byte) 0xB5, (byte) 0x68,
            (byte) 0x8E, (byte) 0xF5, (byte) 0x73, (byte) 0x28,
            (byte) 0x46, (byte) 0x64, (byte) 0x69, (byte) 0x89,
            (byte) 0x68, (byte) 0xC3, (byte) 0x8B, (byte) 0xB9,
            (byte) 0x13, (byte) 0xCB, (byte) 0xFC, (byte) 0x82};

    // second part of G uncompressed
    public static final byte[] EC160_FP_G_Y = new byte[]{
            (byte) 0x23, (byte) 0xA6, (byte) 0x28, (byte) 0x55,
            (byte) 0x31, (byte) 0x68, (byte) 0x94, (byte) 0x7D,
            (byte) 0x59, (byte) 0xDC, (byte) 0xC9, (byte) 0x12,
            (byte) 0x04, (byte) 0x23, (byte) 0x51, (byte) 0x37,
            (byte) 0x7A, (byte) 0xC5, (byte) 0xFB, (byte) 0x32};
    // Order of G
    public static final byte[] EC160_FP_R = new byte[]{
            (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x01, (byte) 0xF4, (byte) 0xC8,
            (byte) 0xF9, (byte) 0x27, (byte) 0xAE, (byte) 0xD3,
            (byte) 0xCA, (byte) 0x75, (byte) 0x22, (byte) 0x57};
    // cofactor of G
    public static final short EC160_FP_K = 1;


    // secp192r1 from http://www.secg.org/sec2-v2.pdf
    public static final byte[] EC192_FP_P = new byte[]{
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
    public static final byte[] EC192_FP_A = new byte[]{
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC};
    public static final byte[] EC192_FP_B = new byte[]{
            (byte) 0x64, (byte) 0x21, (byte) 0x05, (byte) 0x19,
            (byte) 0xE5, (byte) 0x9C, (byte) 0x80, (byte) 0xE7,
            (byte) 0x0F, (byte) 0xA7, (byte) 0xE9, (byte) 0xAB,
            (byte) 0x72, (byte) 0x24, (byte) 0x30, (byte) 0x49,
            (byte) 0xFE, (byte) 0xB8, (byte) 0xDE, (byte) 0xEC,
            (byte) 0xC1, (byte) 0x46, (byte) 0xB9, (byte) 0xB1};
    // G in compressed form / first part of ucompressed
    public static final byte[] EC192_FP_G_X = new byte[]{
            (byte) 0x18, (byte) 0x8D, (byte) 0xA8, (byte) 0x0E,
            (byte) 0xB0, (byte) 0x30, (byte) 0x90, (byte) 0xF6,
            (byte) 0x7C, (byte) 0xBF, (byte) 0x20, (byte) 0xEB,
            (byte) 0x43, (byte) 0xA1, (byte) 0x88, (byte) 0x00,
            (byte) 0xF4, (byte) 0xFF, (byte) 0x0A, (byte) 0xFD,
            (byte) 0x82, (byte) 0xFF, (byte) 0x10, (byte) 0x12};
    // second part of G uncompressed
    public static final byte[] EC192_FP_G_Y = new byte[]{
            (byte) 0x07, (byte) 0x19, (byte) 0x2B, (byte) 0x95,
            (byte) 0xFF, (byte) 0xC8, (byte) 0xDA, (byte) 0x78,
            (byte) 0x63, (byte) 0x10, (byte) 0x11, (byte) 0xED,
            (byte) 0x6B, (byte) 0x24, (byte) 0xCD, (byte) 0xD5,
            (byte) 0x73, (byte) 0xF9, (byte) 0x77, (byte) 0xA1,
            (byte) 0x1E, (byte) 0x79, (byte) 0x48, (byte) 0x11};
    // Order of G
    public static final byte[] EC192_FP_R = new byte[]{
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0x99, (byte) 0xDE, (byte) 0xF8, (byte) 0x36,
            (byte) 0x14, (byte) 0x6B, (byte) 0xC9, (byte) 0xB1,
            (byte) 0xB4, (byte) 0xD2, (byte) 0x28, (byte) 0x31};
    // cofactor of G
    public static final short EC192_FP_K = 1;

    // secp224r1 from http://www.secg.org/sec2-v2.pdf
    public static final byte[] EC224_FP_P = new byte[]{
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01};

    public static final byte[] EC224_FP_A = new byte[]{
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE};

    public static final byte[] EC224_FP_B = new byte[]{
            (byte) 0xB4, (byte) 0x05, (byte) 0x0A, (byte) 0x85,
            (byte) 0x0C, (byte) 0x04, (byte) 0xB3, (byte) 0xAB,
            (byte) 0xF5, (byte) 0x41, (byte) 0x32, (byte) 0x56,
            (byte) 0x50, (byte) 0x44, (byte) 0xB0, (byte) 0xB7,
            (byte) 0xD7, (byte) 0xBF, (byte) 0xD8, (byte) 0xBA,
            (byte) 0x27, (byte) 0x0B, (byte) 0x39, (byte) 0x43,
            (byte) 0x23, (byte) 0x55, (byte) 0xFF, (byte) 0xB4};

    // G in compressed form / first part of ucompressed
    public static final byte[] EC224_FP_G_X = new byte[]{
            (byte) 0xB7, (byte) 0x0E, (byte) 0x0C, (byte) 0xBD,
            (byte) 0x6B, (byte) 0xB4, (byte) 0xBF, (byte) 0x7F,
            (byte) 0x32, (byte) 0x13, (byte) 0x90, (byte) 0xB9,
            (byte) 0x4A, (byte) 0x03, (byte) 0xC1, (byte) 0xD3,
            (byte) 0x56, (byte) 0xC2, (byte) 0x11, (byte) 0x22,
            (byte) 0x34, (byte) 0x32, (byte) 0x80, (byte) 0xD6,
            (byte) 0x11, (byte) 0x5C, (byte) 0x1D, (byte) 0x21};
    // second part of G uncompressed
    public static final byte[] EC224_FP_G_Y = new byte[]{
            (byte) 0xBD, (byte) 0x37, (byte) 0x63, (byte) 0x88,
            (byte) 0xB5, (byte) 0xF7, (byte) 0x23, (byte) 0xFB,
            (byte) 0x4C, (byte) 0x22, (byte) 0xDF, (byte) 0xE6,
            (byte) 0xCD, (byte) 0x43, (byte) 0x75, (byte) 0xA0,
            (byte) 0x5A, (byte) 0x07, (byte) 0x47, (byte) 0x64,
            (byte) 0x44, (byte) 0xD5, (byte) 0x81, (byte) 0x99,
            (byte) 0x85, (byte) 0x00, (byte) 0x7E, (byte) 0x34};
    // Order of G
    public static final byte[] EC224_FP_R = new byte[]{
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0x16, (byte) 0xA2,
            (byte) 0xE0, (byte) 0xB8, (byte) 0xF0, (byte) 0x3E,
            (byte) 0x13, (byte) 0xDD, (byte) 0x29, (byte) 0x45,
            (byte) 0x5C, (byte) 0x5C, (byte) 0x2A, (byte) 0x3D};
    // cofactor of G
    public static final short EC224_FP_K = 1;

    // secp256r1 from http://www.secg.org/sec2-v2.pdf
    public static final byte[] EC256_FP_P = new byte[]{
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
    public static final byte[] EC256_FP_A = new byte[]{
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC};
    public static final byte[] EC256_FP_B = new byte[]{
            (byte) 0x5A, (byte) 0xC6, (byte) 0x35, (byte) 0xD8,
            (byte) 0xAA, (byte) 0x3A, (byte) 0x93, (byte) 0xE7,
            (byte) 0xB3, (byte) 0xEB, (byte) 0xBD, (byte) 0x55,
            (byte) 0x76, (byte) 0x98, (byte) 0x86, (byte) 0xBC,
            (byte) 0x65, (byte) 0x1D, (byte) 0x06, (byte) 0xB0,
            (byte) 0xCC, (byte) 0x53, (byte) 0xB0, (byte) 0xF6,
            (byte) 0x3B, (byte) 0xCE, (byte) 0x3C, (byte) 0x3E,
            (byte) 0x27, (byte) 0xD2, (byte) 0x60, (byte) 0x4B};
    // G in compressed form / first part of ucompressed
    public static final byte[] EC256_FP_G_X = new byte[]{
            (byte) 0x6B, (byte) 0x17, (byte) 0xD1, (byte) 0xF2,
            (byte) 0xE1, (byte) 0x2C, (byte) 0x42, (byte) 0x47,
            (byte) 0xF8, (byte) 0xBC, (byte) 0xE6, (byte) 0xE5,
            (byte) 0x63, (byte) 0xA4, (byte) 0x40, (byte) 0xF2,
            (byte) 0x77, (byte) 0x03, (byte) 0x7D, (byte) 0x81,
            (byte) 0x2D, (byte) 0xEB, (byte) 0x33, (byte) 0xA0,
            (byte) 0xF4, (byte) 0xA1, (byte) 0x39, (byte) 0x45,
            (byte) 0xD8, (byte) 0x98, (byte) 0xC2, (byte) 0x96};
    // second part of G uncompressed
    public static final byte[] EC256_FP_G_Y = new byte[]{
            (byte) 0x4F, (byte) 0xE3, (byte) 0x42, (byte) 0xE2,
            (byte) 0xFE, (byte) 0x1A, (byte) 0x7F, (byte) 0x9B,
            (byte) 0x8E, (byte) 0xE7, (byte) 0xEB, (byte) 0x4A,
            (byte) 0x7C, (byte) 0x0F, (byte) 0x9E, (byte) 0x16,
            (byte) 0x2B, (byte) 0xCE, (byte) 0x33, (byte) 0x57,
            (byte) 0x6B, (byte) 0x31, (byte) 0x5E, (byte) 0xCE,
            (byte) 0xCB, (byte) 0xB6, (byte) 0x40, (byte) 0x68,
            (byte) 0x37, (byte) 0xBF, (byte) 0x51, (byte) 0xF5};
    // Order of G
    public static final byte[] EC256_FP_R = new byte[]{
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xBC, (byte) 0xE6, (byte) 0xFA, (byte) 0xAD,
            (byte) 0xA7, (byte) 0x17, (byte) 0x9E, (byte) 0x84,
            (byte) 0xF3, (byte) 0xB9, (byte) 0xCA, (byte) 0xC2,
            (byte) 0xFC, (byte) 0x63, (byte) 0x25, (byte) 0x51};
    // cofactor of G
    public static final short EC256_FP_K = 1;

    // secp384r1 from http://www.secg.org/sec2-v2.pdf
    public static final byte[] EC384_FP_P = new byte[]{
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};

    public static final byte[] EC384_FP_A = new byte[]{
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC};

    public static final byte[] EC384_FP_B = new byte[]{
            (byte) 0xB3, (byte) 0x31, (byte) 0x2F, (byte) 0xA7,
            (byte) 0xE2, (byte) 0x3E, (byte) 0xE7, (byte) 0xE4,
            (byte) 0x98, (byte) 0x8E, (byte) 0x05, (byte) 0x6B,
            (byte) 0xE3, (byte) 0xF8, (byte) 0x2D, (byte) 0x19,
            (byte) 0x18, (byte) 0x1D, (byte) 0x9C, (byte) 0x6E,
            (byte) 0xFE, (byte) 0x81, (byte) 0x41, (byte) 0x12,
            (byte) 0x03, (byte) 0x14, (byte) 0x08, (byte) 0x8F,
            (byte) 0x50, (byte) 0x13, (byte) 0x87, (byte) 0x5A,
            (byte) 0xC6, (byte) 0x56, (byte) 0x39, (byte) 0x8D,
            (byte) 0x8A, (byte) 0x2E, (byte) 0xD1, (byte) 0x9D,
            (byte) 0x2A, (byte) 0x85, (byte) 0xC8, (byte) 0xED,
            (byte) 0xD3, (byte) 0xEC, (byte) 0x2A, (byte) 0xEF};

    // G in compressed form / first part of ucompressed
    public static final byte[] EC384_FP_G_X = new byte[]{
            (byte) 0xAA, (byte) 0x87, (byte) 0xCA, (byte) 0x22,
            (byte) 0xBE, (byte) 0x8B, (byte) 0x05, (byte) 0x37,
            (byte) 0x8E, (byte) 0xB1, (byte) 0xC7, (byte) 0x1E,
            (byte) 0xF3, (byte) 0x20, (byte) 0xAD, (byte) 0x74,
            (byte) 0x6E, (byte) 0x1D, (byte) 0x3B, (byte) 0x62,
            (byte) 0x8B, (byte) 0xA7, (byte) 0x9B, (byte) 0x98,
            (byte) 0x59, (byte) 0xF7, (byte) 0x41, (byte) 0xE0,
            (byte) 0x82, (byte) 0x54, (byte) 0x2A, (byte) 0x38,
            (byte) 0x55, (byte) 0x02, (byte) 0xF2, (byte) 0x5D,
            (byte) 0xBF, (byte) 0x55, (byte) 0x29, (byte) 0x6C,
            (byte) 0x3A, (byte) 0x54, (byte) 0x5E, (byte) 0x38,
            (byte) 0x72, (byte) 0x76, (byte) 0x0A, (byte) 0xB7};
    // second part of G uncompressed
    public static final byte[] EC384_FP_G_Y = new byte[]{
            (byte) 0x36, (byte) 0x17, (byte) 0xDE, (byte) 0x4A,
            (byte) 0x96, (byte) 0x26, (byte) 0x2C, (byte) 0x6F,
            (byte) 0x5D, (byte) 0x9E, (byte) 0x98, (byte) 0xBF,
            (byte) 0x92, (byte) 0x92, (byte) 0xDC, (byte) 0x29,
            (byte) 0xF8, (byte) 0xF4, (byte) 0x1D, (byte) 0xBD,
            (byte) 0x28, (byte) 0x9A, (byte) 0x14, (byte) 0x7C,
            (byte) 0xE9, (byte) 0xDA, (byte) 0x31, (byte) 0x13,
            (byte) 0xB5, (byte) 0xF0, (byte) 0xB8, (byte) 0xC0,
            (byte) 0x0A, (byte) 0x60, (byte) 0xB1, (byte) 0xCE,
            (byte) 0x1D, (byte) 0x7E, (byte) 0x81, (byte) 0x9D,
            (byte) 0x7A, (byte) 0x43, (byte) 0x1D, (byte) 0x7C,
            (byte) 0x90, (byte) 0xEA, (byte) 0x0E, (byte) 0x5F};

    // Order of G
    public static final byte[] EC384_FP_R = new byte[]{
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xC7, (byte) 0x63, (byte) 0x4D, (byte) 0x81,
            (byte) 0xF4, (byte) 0x37, (byte) 0x2D, (byte) 0xDF,
            (byte) 0x58, (byte) 0x1A, (byte) 0x0D, (byte) 0xB2,
            (byte) 0x48, (byte) 0xB0, (byte) 0xA7, (byte) 0x7A,
            (byte) 0xEC, (byte) 0xEC, (byte) 0x19, (byte) 0x6A,
            (byte) 0xCC, (byte) 0xC5, (byte) 0x29, (byte) 0x73};
    // cofactor of G
    public static final short EC384_FP_K = 1;


    // secp521r1 from http://www.secg.org/sec2-v2.pdf
    public static final byte[] EC521_FP_P = new byte[]{
            (byte) 0x01, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};

    public static final byte[] EC521_FP_A = new byte[]{
            (byte) 0x01, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC};

    public static final byte[] EC521_FP_B = new byte[]{
            (byte) 0x00, (byte) 0x51, (byte) 0x95, (byte) 0x3E,
            (byte) 0xB9, (byte) 0x61, (byte) 0x8E, (byte) 0x1C,
            (byte) 0x9A, (byte) 0x1F, (byte) 0x92, (byte) 0x9A,
            (byte) 0x21, (byte) 0xA0, (byte) 0xB6, (byte) 0x85,
            (byte) 0x40, (byte) 0xEE, (byte) 0xA2, (byte) 0xDA,
            (byte) 0x72, (byte) 0x5B, (byte) 0x99, (byte) 0xB3,
            (byte) 0x15, (byte) 0xF3, (byte) 0xB8, (byte) 0xB4,
            (byte) 0x89, (byte) 0x91, (byte) 0x8E, (byte) 0xF1,
            (byte) 0x09, (byte) 0xE1, (byte) 0x56, (byte) 0x19,
            (byte) 0x39, (byte) 0x51, (byte) 0xEC, (byte) 0x7E,
            (byte) 0x93, (byte) 0x7B, (byte) 0x16, (byte) 0x52,
            (byte) 0xC0, (byte) 0xBD, (byte) 0x3B, (byte) 0xB1,
            (byte) 0xBF, (byte) 0x07, (byte) 0x35, (byte) 0x73,
            (byte) 0xDF, (byte) 0x88, (byte) 0x3D, (byte) 0x2C,
            (byte) 0x34, (byte) 0xF1, (byte) 0xEF, (byte) 0x45,
            (byte) 0x1F, (byte) 0xD4, (byte) 0x6B, (byte) 0x50,
            (byte) 0x3F, (byte) 0x00};

    // G in compressed form / first part of ucompressed
    public static final byte[] EC521_FP_G_X = new byte[]{
            (byte) 0x00, (byte) 0xC6, (byte) 0x85, (byte) 0x8E,
            (byte) 0x06, (byte) 0xB7, (byte) 0x04, (byte) 0x04,
            (byte) 0xE9, (byte) 0xCD, (byte) 0x9E, (byte) 0x3E,
            (byte) 0xCB, (byte) 0x66, (byte) 0x23, (byte) 0x95,
            (byte) 0xB4, (byte) 0x42, (byte) 0x9C, (byte) 0x64,
            (byte) 0x81, (byte) 0x39, (byte) 0x05, (byte) 0x3F,
            (byte) 0xB5, (byte) 0x21, (byte) 0xF8, (byte) 0x28,
            (byte) 0xAF, (byte) 0x60, (byte) 0x6B, (byte) 0x4D,
            (byte) 0x3D, (byte) 0xBA, (byte) 0xA1, (byte) 0x4B,
            (byte) 0x5E, (byte) 0x77, (byte) 0xEF, (byte) 0xE7,
            (byte) 0x59, (byte) 0x28, (byte) 0xFE, (byte) 0x1D,
            (byte) 0xC1, (byte) 0x27, (byte) 0xA2, (byte) 0xFF,
            (byte) 0xA8, (byte) 0xDE, (byte) 0x33, (byte) 0x48,
            (byte) 0xB3, (byte) 0xC1, (byte) 0x85, (byte) 0x6A,
            (byte) 0x42, (byte) 0x9B, (byte) 0xF9, (byte) 0x7E,
            (byte) 0x7E, (byte) 0x31, (byte) 0xC2, (byte) 0xE5,
            (byte) 0xBD, (byte) 0x66};

    // second part of G uncompressed
    public static final byte[] EC521_FP_G_Y = new byte[]{
            (byte) 0x01, (byte) 0x18, (byte) 0x39, (byte) 0x29,
            (byte) 0x6A, (byte) 0x78, (byte) 0x9A, (byte) 0x3B,
            (byte) 0xC0, (byte) 0x04, (byte) 0x5C, (byte) 0x8A,
            (byte) 0x5F, (byte) 0xB4, (byte) 0x2C, (byte) 0x7D,
            (byte) 0x1B, (byte) 0xD9, (byte) 0x98, (byte) 0xF5,
            (byte) 0x44, (byte) 0x49, (byte) 0x57, (byte) 0x9B,
            (byte) 0x44, (byte) 0x68, (byte) 0x17, (byte) 0xAF,
            (byte) 0xBD, (byte) 0x17, (byte) 0x27, (byte) 0x3E,
            (byte) 0x66, (byte) 0x2C, (byte) 0x97, (byte) 0xEE,
            (byte) 0x72, (byte) 0x99, (byte) 0x5E, (byte) 0xF4,
            (byte) 0x26, (byte) 0x40, (byte) 0xC5, (byte) 0x50,
            (byte) 0xB9, (byte) 0x01, (byte) 0x3F, (byte) 0xAD,
            (byte) 0x07, (byte) 0x61, (byte) 0x35, (byte) 0x3C,
            (byte) 0x70, (byte) 0x86, (byte) 0xA2, (byte) 0x72,
            (byte) 0xC2, (byte) 0x40, (byte) 0x88, (byte) 0xBE,
            (byte) 0x94, (byte) 0x76, (byte) 0x9F, (byte) 0xD1,
            (byte) 0x66, (byte) 0x50};

    // Order of G
    public static final byte[] EC521_FP_R = new byte[]{
            (byte) 0x01, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFA,
            (byte) 0x51, (byte) 0x86, (byte) 0x87, (byte) 0x83,
            (byte) 0xBF, (byte) 0x2F, (byte) 0x96, (byte) 0x6B,
            (byte) 0x7F, (byte) 0xCC, (byte) 0x01, (byte) 0x48,
            (byte) 0xF7, (byte) 0x09, (byte) 0xA5, (byte) 0xD0,
            (byte) 0x3B, (byte) 0xB5, (byte) 0xC9, (byte) 0xB8,
            (byte) 0x89, (byte) 0x9C, (byte) 0x47, (byte) 0xAE,
            (byte) 0xBB, (byte) 0x6F, (byte) 0xB7, (byte) 0x1E,
            (byte) 0x91, (byte) 0x38, (byte) 0x64, (byte) 0x09};

    // cofactor of G
    public static final short EC521_FP_K = 1;

    //sect163r1 from http://www.secg.org/sec2-v2.pdf
    // [short i1, short i2, short i3] f = x^163 + x^i1 + x^i2 + x^i3 + 1
    public static final byte[] EC163_F2M_F = new byte[]{
            (byte) 0x00, (byte) 0x07,
            (byte) 0x00, (byte) 0x06,
            (byte) 0x00, (byte) 0x03
    };

    public static final byte[] EC163_F2M_A = new byte[]{
            (byte) 0x07, (byte) 0xB6, (byte) 0x88, (byte) 0x2C,
            (byte) 0xAA, (byte) 0xEF, (byte) 0xA8, (byte) 0x4F,
            (byte) 0x95, (byte) 0x54, (byte) 0xFF, (byte) 0x84,
            (byte) 0x28, (byte) 0xBD, (byte) 0x88, (byte) 0xE2,
            (byte) 0x46, (byte) 0xD2, (byte) 0x78, (byte) 0x2A,
            (byte) 0xE2
    };

    public static final byte[] EC163_F2M_B = new byte[]{
            (byte) 0x07, (byte) 0x13, (byte) 0x61, (byte) 0x2D,
            (byte) 0xCD, (byte) 0xDC, (byte) 0xB4, (byte) 0x0A,
            (byte) 0xAB, (byte) 0x94, (byte) 0x6B, (byte) 0xDA,
            (byte) 0x29, (byte) 0xCA, (byte) 0x91, (byte) 0xF7,
            (byte) 0x3A, (byte) 0xF9, (byte) 0x58, (byte) 0xAF,
            (byte) 0xD9
    };

    // G in compressed form / first part of ucompressed
    public static final byte[] EC163_F2M_G_X = new byte[]{
            (byte) 0x03, (byte) 0x69, (byte) 0x97, (byte) 0x96,
            (byte) 0x97, (byte) 0xAB, (byte) 0x43, (byte) 0x89,
            (byte) 0x77, (byte) 0x89, (byte) 0x56, (byte) 0x67,
            (byte) 0x89, (byte) 0x56, (byte) 0x7F, (byte) 0x78,
            (byte) 0x7A, (byte) 0x78, (byte) 0x76, (byte) 0xA6,
            (byte) 0x54
    };

    // second part of G uncompressed
    public static final byte[] EC163_F2M_G_Y = new byte[]{
            (byte) 0x00, (byte) 0x43, (byte) 0x5E, (byte) 0xDB,
            (byte) 0x42, (byte) 0xEF, (byte) 0xAF, (byte) 0xB2,
            (byte) 0x98, (byte) 0x9D, (byte) 0x51, (byte) 0xFE,
            (byte) 0xFC, (byte) 0xE3, (byte) 0xC8, (byte) 0x09,
            (byte) 0x88, (byte) 0xF4, (byte) 0x1F, (byte) 0xF8,
            (byte) 0x83
    };

    // order of G
    public static final byte[] EC163_F2M_R = new byte[]{
            (byte) 0x03, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x48,
            (byte) 0xAA, (byte) 0xB6, (byte) 0x89, (byte) 0xC2,
            (byte) 0x9C, (byte) 0xA7, (byte) 0x10, (byte) 0x27,
            (byte) 0x9B
    };

    // cofactor of G
    public static final short EC163_F2M_K = 2;

    //sect233r1 from http://www.secg.org/sec2-v2.pdf
    // [short i1, short i2, short i3] f = x^233 + x^i1 + 1
    public static final byte[] EC233_F2M_F = new byte[]{
            (byte) 0x00, (byte) 0x4a
    };

    public static final byte[] EC233_F2M_A = new byte[]{
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x01
    };

    public static final byte[] EC233_F2M_B = new byte[]{
            (byte) 0x00, (byte) 0x66, (byte) 0x64, (byte) 0x7E,
            (byte) 0xDE, (byte) 0x6C, (byte) 0x33, (byte) 0x2C,
            (byte) 0x7F, (byte) 0x8C, (byte) 0x09, (byte) 0x23,
            (byte) 0xBB, (byte) 0x58, (byte) 0x21, (byte) 0x3B,
            (byte) 0x33, (byte) 0x3B, (byte) 0x20, (byte) 0xE9,
            (byte) 0xCE, (byte) 0x42, (byte) 0x81, (byte) 0xFE,
            (byte) 0x11, (byte) 0x5F, (byte) 0x7D, (byte) 0x8F,
            (byte) 0x90, (byte) 0xAD
    };

    // G in compressed form / first part of ucompressed
    public static final byte[] EC233_F2M_G_X = new byte[]{
            (byte) 0x00, (byte) 0xFA, (byte) 0xC9, (byte) 0xDF,
            (byte) 0xCB, (byte) 0xAC, (byte) 0x83, (byte) 0x13,
            (byte) 0xBB, (byte) 0x21, (byte) 0x39, (byte) 0xF1,
            (byte) 0xBB, (byte) 0x75, (byte) 0x5F, (byte) 0xEF,
            (byte) 0x65, (byte) 0xBC, (byte) 0x39, (byte) 0x1F,
            (byte) 0x8B, (byte) 0x36, (byte) 0xF8, (byte) 0xF8,
            (byte) 0xEB, (byte) 0x73, (byte) 0x71, (byte) 0xFD,
            (byte) 0x55, (byte) 0x8B
    };

    // second part of G uncompressed
    public static final byte[] EC233_F2M_G_Y = new byte[]{
            (byte) 0x01, (byte) 0x00, (byte) 0x6A, (byte) 0x08,
            (byte) 0xA4, (byte) 0x19, (byte) 0x03, (byte) 0x35,
            (byte) 0x06, (byte) 0x78, (byte) 0xE5, (byte) 0x85,
            (byte) 0x28, (byte) 0xBE, (byte) 0xBF, (byte) 0x8A,
            (byte) 0x0B, (byte) 0xEF, (byte) 0xF8, (byte) 0x67,
            (byte) 0xA7, (byte) 0xCA, (byte) 0x36, (byte) 0x71,
            (byte) 0x6F, (byte) 0x7E, (byte) 0x01, (byte) 0xF8,
            (byte) 0x10, (byte) 0x52
    };

    // order of G
    public static final byte[] EC233_F2M_R = new byte[]{
            (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x13,
            (byte) 0xE9, (byte) 0x74, (byte) 0xE7, (byte) 0x2F,
            (byte) 0x8A, (byte) 0x69, (byte) 0x22, (byte) 0x03,
            (byte) 0x1D, (byte) 0x26, (byte) 0x03, (byte) 0xCF,
            (byte) 0xE0, (byte) 0xD7
    };

    // cofactor of G
    public static final short EC233_F2M_K = 2;

    //sect283r1 from http://www.secg.org/sec2-v2.pdf
    // [short i1, short i2, short i3] f = x^283 + x^i1 + x^i2 + x^i3 + 1
    public static final byte[] EC283_F2M_F = new byte[]{
            (byte) 0x00, (byte) 0x0c,
            (byte) 0x00, (byte) 0x07,
            (byte) 0x00, (byte) 0x05
    };

    public static final byte[] EC283_F2M_A = new byte[]{
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01
    };

    public static final byte[] EC283_F2M_B = new byte[]{
            (byte) 0x02, (byte) 0x7B, (byte) 0x68, (byte) 0x0A,
            (byte) 0xC8, (byte) 0xB8, (byte) 0x59, (byte) 0x6D,
            (byte) 0xA5, (byte) 0xA4, (byte) 0xAF, (byte) 0x8A,
            (byte) 0x19, (byte) 0xA0, (byte) 0x30, (byte) 0x3F,
            (byte) 0xCA, (byte) 0x97, (byte) 0xFD, (byte) 0x76,
            (byte) 0x45, (byte) 0x30, (byte) 0x9F, (byte) 0xA2,
            (byte) 0xA5, (byte) 0x81, (byte) 0x48, (byte) 0x5A,
            (byte) 0xF6, (byte) 0x26, (byte) 0x3E, (byte) 0x31,
            (byte) 0x3B, (byte) 0x79, (byte) 0xA2, (byte) 0xF5
    };

    // G in compressed form / first part of ucompressed
    public static final byte[] EC283_F2M_G_X = new byte[]{
            (byte) 0x05, (byte) 0xF9, (byte) 0x39, (byte) 0x25,
            (byte) 0x8D, (byte) 0xB7, (byte) 0xDD, (byte) 0x90,
            (byte) 0xE1, (byte) 0x93, (byte) 0x4F, (byte) 0x8C,
            (byte) 0x70, (byte) 0xB0, (byte) 0xDF, (byte) 0xEC,
            (byte) 0x2E, (byte) 0xED, (byte) 0x25, (byte) 0xB8,
            (byte) 0x55, (byte) 0x7E, (byte) 0xAC, (byte) 0x9C,
            (byte) 0x80, (byte) 0xE2, (byte) 0xE1, (byte) 0x98,
            (byte) 0xF8, (byte) 0xCD, (byte) 0xBE, (byte) 0xCD,
            (byte) 0x86, (byte) 0xB1, (byte) 0x20, (byte) 0x53
    };

    // second part of G uncompressed
    public static final byte[] EC283_F2M_G_Y = new byte[]{
            (byte) 0x03, (byte) 0x67, (byte) 0x68, (byte) 0x54,
            (byte) 0xFE, (byte) 0x24, (byte) 0x14, (byte) 0x1C,
            (byte) 0xB9, (byte) 0x8F, (byte) 0xE6, (byte) 0xD4,
            (byte) 0xB2, (byte) 0x0D, (byte) 0x02, (byte) 0xB4,
            (byte) 0x51, (byte) 0x6F, (byte) 0xF7, (byte) 0x02,
            (byte) 0x35, (byte) 0x0E, (byte) 0xDD, (byte) 0xB0,
            (byte) 0x82, (byte) 0x67, (byte) 0x79, (byte) 0xC8,
            (byte) 0x13, (byte) 0xF0, (byte) 0xDF, (byte) 0x45,
            (byte) 0xBE, (byte) 0x81, (byte) 0x12, (byte) 0xF4
    };

    // order of G
    public static final byte[] EC283_F2M_R = new byte[]{
            (byte) 0x03, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xEF, (byte) 0x90,
            (byte) 0x39, (byte) 0x96, (byte) 0x60, (byte) 0xFC,
            (byte) 0x93, (byte) 0x8A, (byte) 0x90, (byte) 0x16,
            (byte) 0x5B, (byte) 0x04, (byte) 0x2A, (byte) 0x7C,
            (byte) 0xEF, (byte) 0xAD, (byte) 0xB3, (byte) 0x07
    };

    // cofactor of G
    public static final short EC283_F2M_K = 2;

    //sect409r1 from http://www.secg.org/sec2-v2.pdf
    // [short i1, short i2, short i3] f = x^409 + x^i1 + 1
    public static final byte[] EC409_F2M_F = new byte[]{
            (byte) 0x00, (byte) 0x57
    };

    public static final byte[] EC409_F2M_A = new byte[]{
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01
    };

    public static final byte[] EC409_F2M_B = new byte[]{
            (byte) 0x00, (byte) 0x21, (byte) 0xA5, (byte) 0xC2,
            (byte) 0xC8, (byte) 0xEE, (byte) 0x9F, (byte) 0xEB,
            (byte) 0x5C, (byte) 0x4B, (byte) 0x9A, (byte) 0x75,
            (byte) 0x3B, (byte) 0x7B, (byte) 0x47, (byte) 0x6B,
            (byte) 0x7F, (byte) 0xD6, (byte) 0x42, (byte) 0x2E,
            (byte) 0xF1, (byte) 0xF3, (byte) 0xDD, (byte) 0x67,
            (byte) 0x47, (byte) 0x61, (byte) 0xFA, (byte) 0x99,
            (byte) 0xD6, (byte) 0xAC, (byte) 0x27, (byte) 0xC8,
            (byte) 0xA9, (byte) 0xA1, (byte) 0x97, (byte) 0xB2,
            (byte) 0x72, (byte) 0x82, (byte) 0x2F, (byte) 0x6C,
            (byte) 0xD5, (byte) 0x7A, (byte) 0x55, (byte) 0xAA,
            (byte) 0x4F, (byte) 0x50, (byte) 0xAE, (byte) 0x31,
            (byte) 0x7B, (byte) 0x13, (byte) 0x54, (byte) 0x5F
    };

    // G in compressed form / first part of ucompressed
    public static final byte[] EC409_F2M_G_X = new byte[]{
            (byte) 0x01, (byte) 0x5D, (byte) 0x48, (byte) 0x60,
            (byte) 0xD0, (byte) 0x88, (byte) 0xDD, (byte) 0xB3,
            (byte) 0x49, (byte) 0x6B, (byte) 0x0C, (byte) 0x60,
            (byte) 0x64, (byte) 0x75, (byte) 0x62, (byte) 0x60,
            (byte) 0x44, (byte) 0x1C, (byte) 0xDE, (byte) 0x4A,
            (byte) 0xF1, (byte) 0x77, (byte) 0x1D, (byte) 0x4D,
            (byte) 0xB0, (byte) 0x1F, (byte) 0xFE, (byte) 0x5B,
            (byte) 0x34, (byte) 0xE5, (byte) 0x97, (byte) 0x03,
            (byte) 0xDC, (byte) 0x25, (byte) 0x5A, (byte) 0x86,
            (byte) 0x8A, (byte) 0x11, (byte) 0x80, (byte) 0x51,
            (byte) 0x56, (byte) 0x03, (byte) 0xAE, (byte) 0xAB,
            (byte) 0x60, (byte) 0x79, (byte) 0x4E, (byte) 0x54,
            (byte) 0xBB, (byte) 0x79, (byte) 0x96, (byte) 0xA7
    };

    // second part of G uncompressed
    public static final byte[] EC409_F2M_G_Y = new byte[]{
            (byte) 0x00, (byte) 0x61, (byte) 0xB1, (byte) 0xCF,
            (byte) 0xAB, (byte) 0x6B, (byte) 0xE5, (byte) 0xF3,
            (byte) 0x2B, (byte) 0xBF, (byte) 0xA7, (byte) 0x83,
            (byte) 0x24, (byte) 0xED, (byte) 0x10, (byte) 0x6A,
            (byte) 0x76, (byte) 0x36, (byte) 0xB9, (byte) 0xC5,
            (byte) 0xA7, (byte) 0xBD, (byte) 0x19, (byte) 0x8D,
            (byte) 0x01, (byte) 0x58, (byte) 0xAA, (byte) 0x4F,
            (byte) 0x54, (byte) 0x88, (byte) 0xD0, (byte) 0x8F,
            (byte) 0x38, (byte) 0x51, (byte) 0x4F, (byte) 0x1F,
            (byte) 0xDF, (byte) 0x4B, (byte) 0x4F, (byte) 0x40,
            (byte) 0xD2, (byte) 0x18, (byte) 0x1B, (byte) 0x36,
            (byte) 0x81, (byte) 0xC3, (byte) 0x64, (byte) 0xBA,
            (byte) 0x02, (byte) 0x73, (byte) 0xC7, (byte) 0x06
    };

    // order of G
    public static final byte[] EC409_F2M_R = new byte[]{
            (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0xE2,
            (byte) 0xAA, (byte) 0xD6, (byte) 0xA6, (byte) 0x12,
            (byte) 0xF3, (byte) 0x33, (byte) 0x07, (byte) 0xBE,
            (byte) 0x5F, (byte) 0xA4, (byte) 0x7C, (byte) 0x3C,
            (byte) 0x9E, (byte) 0x05, (byte) 0x2F, (byte) 0x83,
            (byte) 0x81, (byte) 0x64, (byte) 0xCD, (byte) 0x37,
            (byte) 0xD9, (byte) 0xA2, (byte) 0x11, (byte) 0x73
    };

    // cofactor of G
    public static final short EC409_F2M_K = 2;

    //sect571r1 from http://www.secg.org/sec2-v2.pdf
    // [short i1, short i2, short i3] f = x^571 + x^i1 + x^i2 + x^i3 + 1
    public static final byte[] EC571_F2M_F = new byte[]{
            (byte) 0x00, (byte) 0x0a,
            (byte) 0x00, (byte) 0x05,
            (byte) 0x00, (byte) 0x02,
    };

    public static final byte[] EC571_F2M_A = new byte[]{
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01
    };

    public static final byte[] EC571_F2M_B = new byte[]{
            (byte) 0x02, (byte) 0xF4, (byte) 0x0E, (byte) 0x7E,
            (byte) 0x22, (byte) 0x21, (byte) 0xF2, (byte) 0x95,
            (byte) 0xDE, (byte) 0x29, (byte) 0x71, (byte) 0x17,
            (byte) 0xB7, (byte) 0xF3, (byte) 0xD6, (byte) 0x2F,
            (byte) 0x5C, (byte) 0x6A, (byte) 0x97, (byte) 0xFF,
            (byte) 0xCB, (byte) 0x8C, (byte) 0xEF, (byte) 0xF1,
            (byte) 0xCD, (byte) 0x6B, (byte) 0xA8, (byte) 0xCE,
            (byte) 0x4A, (byte) 0x9A, (byte) 0x18, (byte) 0xAD,
            (byte) 0x84, (byte) 0xFF, (byte) 0xAB, (byte) 0xBD,
            (byte) 0x8E, (byte) 0xFA, (byte) 0x59, (byte) 0x33,
            (byte) 0x2B, (byte) 0xE7, (byte) 0xAD, (byte) 0x67,
            (byte) 0x56, (byte) 0xA6, (byte) 0x6E, (byte) 0x29,
            (byte) 0x4A, (byte) 0xFD, (byte) 0x18, (byte) 0x5A,
            (byte) 0x78, (byte) 0xFF, (byte) 0x12, (byte) 0xAA,
            (byte) 0x52, (byte) 0x0E, (byte) 0x4D, (byte) 0xE7,
            (byte) 0x39, (byte) 0xBA, (byte) 0xCA, (byte) 0x0C,
            (byte) 0x7F, (byte) 0xFE, (byte) 0xFF, (byte) 0x7F,
            (byte) 0x29, (byte) 0x55, (byte) 0x72, (byte) 0x7A
    };

    // G in compressed form / first part of ucompressed
    public static final byte[] EC571_F2M_G_X = new byte[]{
            (byte) 0x03, (byte) 0x03, (byte) 0x00, (byte) 0x1D,
            (byte) 0x34, (byte) 0xB8, (byte) 0x56, (byte) 0x29,
            (byte) 0x6C, (byte) 0x16, (byte) 0xC0, (byte) 0xD4,
            (byte) 0x0D, (byte) 0x3C, (byte) 0xD7, (byte) 0x75,
            (byte) 0x0A, (byte) 0x93, (byte) 0xD1, (byte) 0xD2,
            (byte) 0x95, (byte) 0x5F, (byte) 0xA8, (byte) 0x0A,
            (byte) 0xA5, (byte) 0xF4, (byte) 0x0F, (byte) 0xC8,
            (byte) 0xDB, (byte) 0x7B, (byte) 0x2A, (byte) 0xBD,
            (byte) 0xBD, (byte) 0xE5, (byte) 0x39, (byte) 0x50,
            (byte) 0xF4, (byte) 0xC0, (byte) 0xD2, (byte) 0x93,
            (byte) 0xCD, (byte) 0xD7, (byte) 0x11, (byte) 0xA3,
            (byte) 0x5B, (byte) 0x67, (byte) 0xFB, (byte) 0x14,
            (byte) 0x99, (byte) 0xAE, (byte) 0x60, (byte) 0x03,
            (byte) 0x86, (byte) 0x14, (byte) 0xF1, (byte) 0x39,
            (byte) 0x4A, (byte) 0xBF, (byte) 0xA3, (byte) 0xB4,
            (byte) 0xC8, (byte) 0x50, (byte) 0xD9, (byte) 0x27,
            (byte) 0xE1, (byte) 0xE7, (byte) 0x76, (byte) 0x9C,
            (byte) 0x8E, (byte) 0xEC, (byte) 0x2D, (byte) 0x19
    };

    // second part of G uncompressed
    public static final byte[] EC571_F2M_G_Y = new byte[]{
            (byte) 0x03, (byte) 0x7B, (byte) 0xF2, (byte) 0x73,
            (byte) 0x42, (byte) 0xDA, (byte) 0x63, (byte) 0x9B,
            (byte) 0x6D, (byte) 0xCC, (byte) 0xFF, (byte) 0xFE,
            (byte) 0xB7, (byte) 0x3D, (byte) 0x69, (byte) 0xD7,
            (byte) 0x8C, (byte) 0x6C, (byte) 0x27, (byte) 0xA6,
            (byte) 0x00, (byte) 0x9C, (byte) 0xBB, (byte) 0xCA,
            (byte) 0x19, (byte) 0x80, (byte) 0xF8, (byte) 0x53,
            (byte) 0x39, (byte) 0x21, (byte) 0xE8, (byte) 0xA6,
            (byte) 0x84, (byte) 0x42, (byte) 0x3E, (byte) 0x43,
            (byte) 0xBA, (byte) 0xB0, (byte) 0x8A, (byte) 0x57,
            (byte) 0x62, (byte) 0x91, (byte) 0xAF, (byte) 0x8F,
            (byte) 0x46, (byte) 0x1B, (byte) 0xB2, (byte) 0xA8,
            (byte) 0xB3, (byte) 0x53, (byte) 0x1D, (byte) 0x2F,
            (byte) 0x04, (byte) 0x85, (byte) 0xC1, (byte) 0x9B,
            (byte) 0x16, (byte) 0xE2, (byte) 0xF1, (byte) 0x51,
            (byte) 0x6E, (byte) 0x23, (byte) 0xDD, (byte) 0x3C,
            (byte) 0x1A, (byte) 0x48, (byte) 0x27, (byte) 0xAF,
            (byte) 0x1B, (byte) 0x8A, (byte) 0xC1, (byte) 0x5B
    };

    // order of G
    public static final byte[] EC571_F2M_R = new byte[]{
            (byte) 0x03, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xE6, (byte) 0x61, (byte) 0xCE, (byte) 0x18,
            (byte) 0xFF, (byte) 0x55, (byte) 0x98, (byte) 0x73,
            (byte) 0x08, (byte) 0x05, (byte) 0x9B, (byte) 0x18,
            (byte) 0x68, (byte) 0x23, (byte) 0x85, (byte) 0x1E,
            (byte) 0xC7, (byte) 0xDD, (byte) 0x9C, (byte) 0xA1,
            (byte) 0x16, (byte) 0x1D, (byte) 0xE9, (byte) 0x3D,
            (byte) 0x51, (byte) 0x74, (byte) 0xD6, (byte) 0x6E,
            (byte) 0x83, (byte) 0x82, (byte) 0xE9, (byte) 0xBB,
            (byte) 0x2F, (byte) 0xE8, (byte) 0x4E, (byte) 0x47
    };

    // cofactor of G
    public static final short EC571_F2M_K = 2;

    //Anomalous curve(small-pub-128), with pubkey of order 5
    public static final byte[] ECSP128_FP_P = {
            (byte) 0xcf, (byte) 0xba, (byte) 0x21, (byte) 0xfd,
            (byte) 0x04, (byte) 0x83, (byte) 0xb1, (byte) 0xf3,
            (byte) 0x00, (byte) 0xfa, (byte) 0x25, (byte) 0x06,
            (byte) 0xa5, (byte) 0xa5, (byte) 0x66, (byte) 0xef
    };

    public static final byte[] ECSP128_FP_A = {
            (byte) 0x36, (byte) 0xd9, (byte) 0xa5, (byte) 0xac,
            (byte) 0xac, (byte) 0x27, (byte) 0xa0, (byte) 0x08,
            (byte) 0xe3, (byte) 0x6c, (byte) 0xbe, (byte) 0x3e,
            (byte) 0x9f, (byte) 0x10, (byte) 0x3f, (byte) 0xde
    };

    public static final byte[] ECSP128_FP_B = {
            (byte) 0xa6, (byte) 0x7c, (byte) 0xf5, (byte) 0xfa,
            (byte) 0x09, (byte) 0xfb, (byte) 0x1d, (byte) 0xb9,
            (byte) 0x02, (byte) 0x06, (byte) 0x8c, (byte) 0x87,
            (byte) 0x04, (byte) 0x6a, (byte) 0xe2, (byte) 0x1e
    };

    public static final byte[] ECSP128_FP_G_X = {
            (byte) 0x47, (byte) 0xd7, (byte) 0x83, (byte) 0x91,
            (byte) 0xa4, (byte) 0xb9, (byte) 0xff, (byte) 0xf6,
            (byte) 0xa0, (byte) 0xdb, (byte) 0x12, (byte) 0x92,
            (byte) 0xf9, (byte) 0xcd, (byte) 0x0e, (byte) 0x6a
    };

    public static final byte[] ECSP128_FP_G_Y = {
            (byte) 0x9a, (byte) 0xed, (byte) 0x9c, (byte) 0x92,
            (byte) 0xf8, (byte) 0xbb, (byte) 0x3d, (byte) 0xbd,
            (byte) 0x42, (byte) 0x40, (byte) 0x21, (byte) 0x65,
            (byte) 0xa2, (byte) 0x70, (byte) 0xbd, (byte) 0x6f
    };

    public static final byte[] ECSP128_FP_R = {
            (byte) 0xcf, (byte) 0xba, (byte) 0x21, (byte) 0xfd,
            (byte) 0x04, (byte) 0x83, (byte) 0xb1, (byte) 0xf3,
            (byte) 0x33, (byte) 0xd6, (byte) 0x1a, (byte) 0x5a,
            (byte) 0xf6, (byte) 0xad, (byte) 0xa2, (byte) 0xc7
    };

    public static final short ECSP128_FP_K = 1;

    public static final byte[] ECSP128_FP_W_X = {
            (byte) 0x63, (byte) 0x90, (byte) 0x1e, (byte) 0x12,
            (byte) 0x27, (byte) 0x61, (byte) 0xd9, (byte) 0xc1,
            (byte) 0x65, (byte) 0x65, (byte) 0xb2, (byte) 0xf3,
            (byte) 0x8e, (byte) 0x99, (byte) 0x1f, (byte) 0x71
    };

    public static final byte[] ECSP128_FP_W_Y = {
            (byte) 0xb9, (byte) 0xd9, (byte) 0x9f, (byte) 0xbc,
            (byte) 0x31, (byte) 0x54, (byte) 0xa9, (byte) 0x6c,
            (byte) 0xa2, (byte) 0x3e, (byte) 0xcf, (byte) 0xf7,
            (byte) 0x70, (byte) 0xcb, (byte) 0xbe, (byte) 0x4f
    };


    //Anomalous curve(small-pub-160), with pubkey of order 3
    public static final byte[] ECSP160_FP_P = {
            (byte) 0xdc, (byte) 0x13, (byte) 0x49, (byte) 0x0f,
            (byte) 0xf9, (byte) 0x85, (byte) 0x7b, (byte) 0x11,
            (byte) 0x1f, (byte) 0x44, (byte) 0xc0, (byte) 0x50,
            (byte) 0x07, (byte) 0x70, (byte) 0xa6, (byte) 0x45,
            (byte) 0x7e, (byte) 0x68, (byte) 0x32, (byte) 0x23
    };

    public static final byte[] ECSP160_FP_A = {
            (byte) 0xa3, (byte) 0xec, (byte) 0xd7, (byte) 0xd5,
            (byte) 0x1e, (byte) 0x79, (byte) 0xd7, (byte) 0x2d,
            (byte) 0x27, (byte) 0x00, (byte) 0x18, (byte) 0x4c,
            (byte) 0x79, (byte) 0x5a, (byte) 0xa8, (byte) 0xa6,
            (byte) 0xb8, (byte) 0xe6, (byte) 0x65, (byte) 0x73
    };

    public static final byte[] ECSP160_FP_B = {
            (byte) 0x8a, (byte) 0xc4, (byte) 0x35, (byte) 0x92,
            (byte) 0x90, (byte) 0x5f, (byte) 0x99, (byte) 0x5c,
            (byte) 0xb1, (byte) 0x3f, (byte) 0x36, (byte) 0x94,
            (byte) 0x31, (byte) 0x7b, (byte) 0xf4, (byte) 0x70,
            (byte) 0xad, (byte) 0xaf, (byte) 0xb6, (byte) 0x45
    };

    public static final byte[] ECSP160_FP_G_X = {
            (byte) 0x5f, (byte) 0x8e, (byte) 0x88, (byte) 0xaf,
            (byte) 0xc1, (byte) 0x17, (byte) 0xc7, (byte) 0x22,
            (byte) 0x85, (byte) 0x9f, (byte) 0xe8, (byte) 0xe5,
            (byte) 0x56, (byte) 0x47, (byte) 0xbc, (byte) 0xa6,
            (byte) 0x9b, (byte) 0xa8, (byte) 0x21, (byte) 0x50
    };

    public static final byte[] ECSP160_FP_G_Y = {
            (byte) 0x93, (byte) 0xe6, (byte) 0xdc, (byte) 0xae,
            (byte) 0xe2, (byte) 0x71, (byte) 0xe9, (byte) 0xf2,
            (byte) 0x83, (byte) 0x8c, (byte) 0x98, (byte) 0xb7,
            (byte) 0xd0, (byte) 0x6e, (byte) 0xcc, (byte) 0xc5,
            (byte) 0xd7, (byte) 0xc8, (byte) 0x00, (byte) 0xe5
    };

    public static final byte[] ECSP160_FP_R = {
            (byte) 0xdc, (byte) 0x13, (byte) 0x49, (byte) 0x0f,
            (byte) 0xf9, (byte) 0x85, (byte) 0x7b, (byte) 0x11,
            (byte) 0x1f, (byte) 0x44, (byte) 0x6e, (byte) 0xf4,
            (byte) 0xa6, (byte) 0xd1, (byte) 0xe1, (byte) 0x71,
            (byte) 0x5f, (byte) 0x6a, (byte) 0x6d, (byte) 0xff
    };

    public static final short ECSP160_FP_K = 1;

    public static final byte[] ECSP160_FP_W_X = {
            (byte) 0x59, (byte) 0xc9, (byte) 0xc3, (byte) 0xc8,
            (byte) 0xae, (byte) 0xf2, (byte) 0x9f, (byte) 0x1c,
            (byte) 0x1c, (byte) 0x50, (byte) 0x0c, (byte) 0xaf,
            (byte) 0xb4, (byte) 0x72, (byte) 0x6d, (byte) 0xa6,
            (byte) 0x08, (byte) 0x6e, (byte) 0x6e, (byte) 0xb0
    };

    public static final byte[] ECSP160_FP_W_Y = {
            (byte) 0xd6, (byte) 0x95, (byte) 0xa7, (byte) 0x60,
            (byte) 0x05, (byte) 0xed, (byte) 0xdb, (byte) 0x26,
            (byte) 0xaf, (byte) 0xd4, (byte) 0x0e, (byte) 0xe2,
            (byte) 0x09, (byte) 0x04, (byte) 0x77, (byte) 0x8b,
            (byte) 0xb3, (byte) 0x49, (byte) 0x7b, (byte) 0xb1
    };


    //Anomalous curve(small-pub-192), with pubkey of order 4
    public static final byte[] ECSP192_FP_P = {
            (byte) 0xee, (byte) 0x8a, (byte) 0x97, (byte) 0x03,
            (byte) 0x3b, (byte) 0xb1, (byte) 0x00, (byte) 0x60,
            (byte) 0x0c, (byte) 0x3a, (byte) 0x9f, (byte) 0x9d,
            (byte) 0x88, (byte) 0x2a, (byte) 0xca, (byte) 0xeb,
            (byte) 0x6e, (byte) 0x24, (byte) 0xfc, (byte) 0x63,
            (byte) 0x04, (byte) 0xd8, (byte) 0x60, (byte) 0x8f
    };

    public static final byte[] ECSP192_FP_A = {
            (byte) 0xc3, (byte) 0xf5, (byte) 0x83, (byte) 0x61,
            (byte) 0x41, (byte) 0x18, (byte) 0xd6, (byte) 0xc4,
            (byte) 0x85, (byte) 0xde, (byte) 0x1c, (byte) 0xd9,
            (byte) 0x0a, (byte) 0x86, (byte) 0xda, (byte) 0x7d,
            (byte) 0xff, (byte) 0x3a, (byte) 0xa6, (byte) 0xbb,
            (byte) 0x77, (byte) 0x5c, (byte) 0xe1, (byte) 0x24
    };

    public static final byte[] ECSP192_FP_B = {
            (byte) 0x96, (byte) 0x78, (byte) 0x63, (byte) 0x29,
            (byte) 0x6d, (byte) 0x32, (byte) 0x01, (byte) 0x61,
            (byte) 0xe6, (byte) 0x88, (byte) 0x0f, (byte) 0xa6,
            (byte) 0xd9, (byte) 0xa4, (byte) 0x86, (byte) 0x79,
            (byte) 0xdf, (byte) 0xdb, (byte) 0xb1, (byte) 0x2b,
            (byte) 0xb7, (byte) 0xe3, (byte) 0x54, (byte) 0xb1
    };

    public static final byte[] ECSP192_FP_G_X = {
            (byte) 0x7d, (byte) 0x6e, (byte) 0x93, (byte) 0x4a,
            (byte) 0xbb, (byte) 0x41, (byte) 0x6c, (byte) 0x64,
            (byte) 0xd4, (byte) 0x28, (byte) 0x90, (byte) 0xea,
            (byte) 0x64, (byte) 0x40, (byte) 0xf5, (byte) 0x8a,
            (byte) 0x0a, (byte) 0x5c, (byte) 0x5b, (byte) 0x31,
            (byte) 0x2f, (byte) 0x35, (byte) 0x6b, (byte) 0x29
    };

    public static final byte[] ECSP192_FP_G_Y = {
            (byte) 0x47, (byte) 0x37, (byte) 0x7f, (byte) 0xed,
            (byte) 0x17, (byte) 0xe2, (byte) 0x31, (byte) 0x74,
            (byte) 0xf1, (byte) 0xb1, (byte) 0xb9, (byte) 0x01,
            (byte) 0x6e, (byte) 0x28, (byte) 0x5e, (byte) 0x9c,
            (byte) 0xac, (byte) 0x39, (byte) 0xe3, (byte) 0xbc,
            (byte) 0xaa, (byte) 0x65, (byte) 0x22, (byte) 0xfd
    };

    public static final byte[] ECSP192_FP_R = {
            (byte) 0xee, (byte) 0x8a, (byte) 0x97, (byte) 0x03,
            (byte) 0x3b, (byte) 0xb1, (byte) 0x00, (byte) 0x60,
            (byte) 0x0c, (byte) 0x3a, (byte) 0x9f, (byte) 0x9e,
            (byte) 0xcd, (byte) 0x2b, (byte) 0xb6, (byte) 0x46,
            (byte) 0x75, (byte) 0x84, (byte) 0x34, (byte) 0xad,
            (byte) 0xd3, (byte) 0xd0, (byte) 0xdf, (byte) 0xd0
    };

    public static final short ECSP192_FP_K = 1;

    public static final byte[] ECSP192_FP_W_X = {
            (byte) 0xaa, (byte) 0xd0, (byte) 0xdb, (byte) 0xf8,
            (byte) 0xad, (byte) 0x1c, (byte) 0x2c, (byte) 0x4e,
            (byte) 0xf0, (byte) 0x67, (byte) 0xda, (byte) 0x63,
            (byte) 0x97, (byte) 0x23, (byte) 0xe2, (byte) 0x0d,
            (byte) 0xcf, (byte) 0xb4, (byte) 0x53, (byte) 0x52,
            (byte) 0xb7, (byte) 0x7a, (byte) 0x59, (byte) 0x9c
    };

    public static final byte[] ECSP192_FP_W_Y = {
            (byte) 0xae, (byte) 0x28, (byte) 0xd7, (byte) 0xea,
            (byte) 0xde, (byte) 0xba, (byte) 0x10, (byte) 0x48,
            (byte) 0x40, (byte) 0x64, (byte) 0x0d, (byte) 0x9b,
            (byte) 0x6e, (byte) 0x2c, (byte) 0x2d, (byte) 0x22,
            (byte) 0x25, (byte) 0xd2, (byte) 0x5d, (byte) 0x79,
            (byte) 0x3a, (byte) 0x65, (byte) 0x5f, (byte) 0xb1
    };


    public static final byte[] ECSP224_FP_P = {
            (byte) 0xee, (byte) 0xd4, (byte) 0xc3, (byte) 0xd9,
            (byte) 0x8f, (byte) 0x1c, (byte) 0x9b, (byte) 0x95,
            (byte) 0x18, (byte) 0xf1, (byte) 0x16, (byte) 0x26,
            (byte) 0x3d, (byte) 0xb7, (byte) 0x70, (byte) 0x36,
            (byte) 0x68, (byte) 0x77, (byte) 0xd1, (byte) 0x2d,
            (byte) 0xf6, (byte) 0xa9, (byte) 0xcf, (byte) 0x08,
            (byte) 0xb9, (byte) 0x6d, (byte) 0xd4, (byte) 0xbb
    };

    //Anomalous curve(small-pub-224), with pubkey of order 5
    public static final byte[] ECSP224_FP_A = {
            (byte) 0x8d, (byte) 0x4d, (byte) 0xdd, (byte) 0xb0,
            (byte) 0x31, (byte) 0x7d, (byte) 0x6a, (byte) 0x6b,
            (byte) 0xf9, (byte) 0xa4, (byte) 0xdb, (byte) 0xbe,
            (byte) 0xd3, (byte) 0xa4, (byte) 0x3f, (byte) 0xa2,
            (byte) 0x1f, (byte) 0x79, (byte) 0x86, (byte) 0x9c,
            (byte) 0x5a, (byte) 0xb9, (byte) 0x72, (byte) 0x9d,
            (byte) 0x23, (byte) 0x9e, (byte) 0x92, (byte) 0x82
    };

    public static final byte[] ECSP224_FP_B = {
            (byte) 0x46, (byte) 0x87, (byte) 0x36, (byte) 0x14,
            (byte) 0xbe, (byte) 0x3d, (byte) 0xff, (byte) 0xc9,
            (byte) 0x21, (byte) 0x80, (byte) 0x82, (byte) 0x32,
            (byte) 0x22, (byte) 0x10, (byte) 0xc0, (byte) 0x61,
            (byte) 0x61, (byte) 0x40, (byte) 0x28, (byte) 0x6f,
            (byte) 0x2d, (byte) 0x16, (byte) 0x05, (byte) 0x03,
            (byte) 0xc1, (byte) 0xa9, (byte) 0x25, (byte) 0x0d
    };

    public static final byte[] ECSP224_FP_G_X = {
            (byte) 0x96, (byte) 0x1b, (byte) 0xbb, (byte) 0x1f,
            (byte) 0xc9, (byte) 0x95, (byte) 0x5a, (byte) 0x71,
            (byte) 0xc9, (byte) 0x1a, (byte) 0x50, (byte) 0xae,
            (byte) 0xdc, (byte) 0xd2, (byte) 0xf1, (byte) 0x4f,
            (byte) 0xcc, (byte) 0xb6, (byte) 0x60, (byte) 0xaf,
            (byte) 0x99, (byte) 0x2b, (byte) 0x00, (byte) 0x30,
            (byte) 0xb9, (byte) 0xc9, (byte) 0x0b, (byte) 0x36
    };

    public static final byte[] ECSP224_FP_G_Y = {
            (byte) 0x1c, (byte) 0x00, (byte) 0xf6, (byte) 0xd0,
            (byte) 0xbd, (byte) 0x40, (byte) 0x5d, (byte) 0xd7,
            (byte) 0xd3, (byte) 0x01, (byte) 0x6f, (byte) 0xb8,
            (byte) 0xc0, (byte) 0xc7, (byte) 0x5e, (byte) 0x4e,
            (byte) 0xce, (byte) 0xc7, (byte) 0x0f, (byte) 0xe6,
            (byte) 0x12, (byte) 0x37, (byte) 0xf6, (byte) 0xd2,
            (byte) 0x40, (byte) 0x08, (byte) 0xa5, (byte) 0xfd
    };

    public static final byte[] ECSP224_FP_R = {
            (byte) 0xee, (byte) 0xd4, (byte) 0xc3, (byte) 0xd9,
            (byte) 0x8f, (byte) 0x1c, (byte) 0x9b, (byte) 0x95,
            (byte) 0x18, (byte) 0xf1, (byte) 0x16, (byte) 0x26,
            (byte) 0x3d, (byte) 0xb8, (byte) 0x21, (byte) 0xc3,
            (byte) 0x6a, (byte) 0x06, (byte) 0xad, (byte) 0xae,
            (byte) 0x17, (byte) 0x16, (byte) 0x2a, (byte) 0xd3,
            (byte) 0x16, (byte) 0x2f, (byte) 0x68, (byte) 0xc3
    };

    public static final short ECSP224_FP_K = 1;

    public static final byte[] ECSP224_FP_W_X = {
            (byte) 0xcf, (byte) 0xd9, (byte) 0x2a, (byte) 0xea,
            (byte) 0x0f, (byte) 0x79, (byte) 0x19, (byte) 0x0c,
            (byte) 0x48, (byte) 0xca, (byte) 0x70, (byte) 0x3e,
            (byte) 0xb8, (byte) 0xa9, (byte) 0xba, (byte) 0xa7,
            (byte) 0x09, (byte) 0x9a, (byte) 0x23, (byte) 0xbb,
            (byte) 0x39, (byte) 0x57, (byte) 0x82, (byte) 0x61,
            (byte) 0xfe, (byte) 0x4d, (byte) 0x0f, (byte) 0x04
    };

    public static final byte[] ECSP224_FP_W_Y = {
            (byte) 0x25, (byte) 0x7a, (byte) 0x3d, (byte) 0x98,
            (byte) 0xde, (byte) 0x44, (byte) 0xbd, (byte) 0x25,
            (byte) 0x40, (byte) 0x49, (byte) 0x77, (byte) 0xa4,
            (byte) 0xac, (byte) 0x7f, (byte) 0xc5, (byte) 0x6d,
            (byte) 0x3d, (byte) 0x4e, (byte) 0x82, (byte) 0x7f,
            (byte) 0x08, (byte) 0x5b, (byte) 0x7c, (byte) 0xf5,
            (byte) 0x24, (byte) 0x75, (byte) 0x24, (byte) 0xc4
    };


    //Anomalous curve(small-pub-256), with pubkey of order 3
    public static final byte[] ECSP256_FP_P = {
            (byte) 0xc9, (byte) 0xa8, (byte) 0x03, (byte) 0xb1,
            (byte) 0xea, (byte) 0xf8, (byte) 0x49, (byte) 0xf1,
            (byte) 0xc0, (byte) 0x2c, (byte) 0xfd, (byte) 0x1d,
            (byte) 0xbf, (byte) 0xac, (byte) 0x68, (byte) 0x62,
            (byte) 0x39, (byte) 0x85, (byte) 0xc8, (byte) 0x8b,
            (byte) 0x37, (byte) 0x10, (byte) 0x3b, (byte) 0x33,
            (byte) 0x8a, (byte) 0xe1, (byte) 0x1d, (byte) 0x25,
            (byte) 0x97, (byte) 0xee, (byte) 0x84, (byte) 0x45
    };

    public static final byte[] ECSP256_FP_A = {
            (byte) 0x48, (byte) 0x41, (byte) 0xc5, (byte) 0x77,
            (byte) 0x5a, (byte) 0x24, (byte) 0xa8, (byte) 0x84,
            (byte) 0xca, (byte) 0x36, (byte) 0xec, (byte) 0x36,
            (byte) 0x2b, (byte) 0x44, (byte) 0x64, (byte) 0x5a,
            (byte) 0x2f, (byte) 0x60, (byte) 0xb2, (byte) 0x5d,
            (byte) 0x00, (byte) 0x2c, (byte) 0x4f, (byte) 0xc1,
            (byte) 0xd9, (byte) 0xf1, (byte) 0x39, (byte) 0x87,
            (byte) 0x0f, (byte) 0xe0, (byte) 0xcc, (byte) 0x71
    };

    public static final byte[] ECSP256_FP_B = {
            (byte) 0x1b, (byte) 0x09, (byte) 0x74, (byte) 0x56,
            (byte) 0x75, (byte) 0x1f, (byte) 0x35, (byte) 0x34,
            (byte) 0x19, (byte) 0x0d, (byte) 0xae, (byte) 0x56,
            (byte) 0x8f, (byte) 0x80, (byte) 0xa2, (byte) 0xc6,
            (byte) 0xff, (byte) 0x55, (byte) 0xdd, (byte) 0xdf,
            (byte) 0xe0, (byte) 0x72, (byte) 0xa7, (byte) 0xdc,
            (byte) 0x64, (byte) 0x67, (byte) 0xa4, (byte) 0xb6,
            (byte) 0x47, (byte) 0x6b, (byte) 0x68, (byte) 0x80
    };

    public static final byte[] ECSP256_FP_G_X = {
            (byte) 0xa1, (byte) 0xfd, (byte) 0x34, (byte) 0xa2,
            (byte) 0x7a, (byte) 0xfb, (byte) 0x13, (byte) 0x40,
            (byte) 0xb8, (byte) 0xe4, (byte) 0xa7, (byte) 0xdb,
            (byte) 0x2a, (byte) 0x5e, (byte) 0xc5, (byte) 0xa1,
            (byte) 0x43, (byte) 0x2c, (byte) 0x6d, (byte) 0xc8,
            (byte) 0x55, (byte) 0x5a, (byte) 0xf9, (byte) 0xf7,
            (byte) 0x8f, (byte) 0xca, (byte) 0x2c, (byte) 0xf7,
            (byte) 0x40, (byte) 0xca, (byte) 0xb2, (byte) 0xb7
    };

    public static final byte[] ECSP256_FP_G_Y = {
            (byte) 0x98, (byte) 0x41, (byte) 0x9c, (byte) 0x69,
            (byte) 0x8c, (byte) 0xab, (byte) 0x6c, (byte) 0x7d,
            (byte) 0xbb, (byte) 0x53, (byte) 0xeb, (byte) 0x27,
            (byte) 0x51, (byte) 0x41, (byte) 0x7b, (byte) 0x52,
            (byte) 0xcc, (byte) 0xde, (byte) 0xd4, (byte) 0x68,
            (byte) 0x0c, (byte) 0x5e, (byte) 0x09, (byte) 0x54,
            (byte) 0x3f, (byte) 0x93, (byte) 0xc7, (byte) 0x88,
            (byte) 0x6c, (byte) 0x3a, (byte) 0x17, (byte) 0x3e
    };

    public static final byte[] ECSP256_FP_R = {
            (byte) 0xc9, (byte) 0xa8, (byte) 0x03, (byte) 0xb1,
            (byte) 0xea, (byte) 0xf8, (byte) 0x49, (byte) 0xf1,
            (byte) 0xc0, (byte) 0x2c, (byte) 0xfd, (byte) 0x1d,
            (byte) 0xbf, (byte) 0xac, (byte) 0x68, (byte) 0x63,
            (byte) 0x12, (byte) 0x8c, (byte) 0x5b, (byte) 0x1f,
            (byte) 0xc5, (byte) 0xac, (byte) 0xd5, (byte) 0xb5,
            (byte) 0xe0, (byte) 0xfc, (byte) 0x0a, (byte) 0x73,
            (byte) 0x11, (byte) 0xfb, (byte) 0x5b, (byte) 0x1d
    };

    public static final short ECSP256_FP_K = 1;

    public static final byte[] ECSP256_FP_W_X = {
            (byte) 0x75, (byte) 0xfc, (byte) 0xe7, (byte) 0x09,
            (byte) 0x68, (byte) 0x86, (byte) 0x2d, (byte) 0x53,
            (byte) 0xe2, (byte) 0x95, (byte) 0x48, (byte) 0xaa,
            (byte) 0xd7, (byte) 0x05, (byte) 0x82, (byte) 0x51,
            (byte) 0x4e, (byte) 0x96, (byte) 0x0d, (byte) 0x81,
            (byte) 0x28, (byte) 0xbd, (byte) 0x3c, (byte) 0x5f,
            (byte) 0x8c, (byte) 0x4d, (byte) 0xbe, (byte) 0x2c,
            (byte) 0xf8, (byte) 0xda, (byte) 0xd6, (byte) 0x53
    };

    public static final byte[] ECSP256_FP_W_Y = {
            (byte) 0x55, (byte) 0xaa, (byte) 0x4b, (byte) 0x7d,
            (byte) 0x38, (byte) 0x82, (byte) 0xfb, (byte) 0x0a,
            (byte) 0x83, (byte) 0xbd, (byte) 0x00, (byte) 0xc9,
            (byte) 0xc3, (byte) 0xba, (byte) 0xe1, (byte) 0x7f,
            (byte) 0x10, (byte) 0x24, (byte) 0xd6, (byte) 0x4a,
            (byte) 0xec, (byte) 0x67, (byte) 0xe1, (byte) 0xdb,
            (byte) 0x38, (byte) 0xef, (byte) 0x67, (byte) 0x1e,
            (byte) 0x63, (byte) 0x50, (byte) 0xbe, (byte) 0xae
    };


    //Anomalous curve(small-pub-384), with pubkey of order 3
    public static final byte[] ECSP384_FP_P = {
            (byte) 0xd0, (byte) 0xdf, (byte) 0x6c, (byte) 0x96,
            (byte) 0xcf, (byte) 0xf7, (byte) 0x08, (byte) 0x1b,
            (byte) 0xe8, (byte) 0x0d, (byte) 0x22, (byte) 0xb0,
            (byte) 0x05, (byte) 0x75, (byte) 0x8a, (byte) 0x2e,
            (byte) 0x2f, (byte) 0x04, (byte) 0x6e, (byte) 0x15,
            (byte) 0xfe, (byte) 0x02, (byte) 0x0e, (byte) 0xf8,
            (byte) 0x86, (byte) 0xe2, (byte) 0x1b, (byte) 0x49,
            (byte) 0x2a, (byte) 0xc5, (byte) 0x72, (byte) 0x57,
            (byte) 0xa9, (byte) 0x23, (byte) 0x14, (byte) 0x4b,
            (byte) 0xca, (byte) 0xd9, (byte) 0x89, (byte) 0xab,
            (byte) 0x63, (byte) 0x41, (byte) 0xbd, (byte) 0x3b,
            (byte) 0x70, (byte) 0x0f, (byte) 0x91, (byte) 0x4b
    };

    public static final byte[] ECSP384_FP_A = {
            (byte) 0x45, (byte) 0xc6, (byte) 0x45, (byte) 0x03,
            (byte) 0xbe, (byte) 0x01, (byte) 0x9a, (byte) 0xfd,
            (byte) 0x34, (byte) 0x62, (byte) 0xb3, (byte) 0x61,
            (byte) 0xad, (byte) 0x2b, (byte) 0x2a, (byte) 0x3b,
            (byte) 0xca, (byte) 0x0a, (byte) 0xec, (byte) 0xcc,
            (byte) 0x54, (byte) 0x94, (byte) 0xa6, (byte) 0x24,
            (byte) 0xfb, (byte) 0x63, (byte) 0x24, (byte) 0x55,
            (byte) 0xe6, (byte) 0x2b, (byte) 0x4f, (byte) 0x0c,
            (byte) 0x98, (byte) 0xf9, (byte) 0x44, (byte) 0xfa,
            (byte) 0x97, (byte) 0xc3, (byte) 0x78, (byte) 0x11,
            (byte) 0xda, (byte) 0x03, (byte) 0x98, (byte) 0x23,
            (byte) 0xcd, (byte) 0x77, (byte) 0xc9, (byte) 0x06
    };

    public static final byte[] ECSP384_FP_B = {
            (byte) 0xd8, (byte) 0x55, (byte) 0x83, (byte) 0xf7,
            (byte) 0xf1, (byte) 0x1a, (byte) 0xd2, (byte) 0x3e,
            (byte) 0xc7, (byte) 0x5e, (byte) 0xd5, (byte) 0xa4,
            (byte) 0x14, (byte) 0x15, (byte) 0x3a, (byte) 0x06,
            (byte) 0xd6, (byte) 0x64, (byte) 0x09, (byte) 0x36,
            (byte) 0xb8, (byte) 0x10, (byte) 0x3f, (byte) 0x5d,
            (byte) 0xf6, (byte) 0x91, (byte) 0xfa, (byte) 0x95,
            (byte) 0xcf, (byte) 0x2a, (byte) 0xfa, (byte) 0x78,
            (byte) 0xf3, (byte) 0xea, (byte) 0x5a, (byte) 0xdd,
            (byte) 0xc2, (byte) 0x25, (byte) 0xb1, (byte) 0x44,
            (byte) 0x96, (byte) 0x40, (byte) 0x48, (byte) 0xc9,
            (byte) 0xf7, (byte) 0x59, (byte) 0x2a, (byte) 0xe4
    };

    public static final byte[] ECSP384_FP_G_X = {
            (byte) 0x2b, (byte) 0x13, (byte) 0x41, (byte) 0xd1,
            (byte) 0x2d, (byte) 0xff, (byte) 0x4f, (byte) 0x9c,
            (byte) 0xf9, (byte) 0x42, (byte) 0x7c, (byte) 0x47,
            (byte) 0x52, (byte) 0x96, (byte) 0x2b, (byte) 0x4c,
            (byte) 0x2b, (byte) 0xdc, (byte) 0x8f, (byte) 0xbc,
            (byte) 0xd8, (byte) 0x06, (byte) 0x52, (byte) 0x51,
            (byte) 0x6c, (byte) 0x42, (byte) 0x1c, (byte) 0xc5,
            (byte) 0x23, (byte) 0x21, (byte) 0x2a, (byte) 0x01,
            (byte) 0xea, (byte) 0x63, (byte) 0xc7, (byte) 0x9d,
            (byte) 0x6e, (byte) 0x9a, (byte) 0x9c, (byte) 0x84,
            (byte) 0x93, (byte) 0x3e, (byte) 0x35, (byte) 0x3e,
            (byte) 0x21, (byte) 0x24, (byte) 0x16, (byte) 0xec
    };

    public static final byte[] ECSP384_FP_G_Y = {
            (byte) 0xce, (byte) 0x41, (byte) 0x6c, (byte) 0x6e,
            (byte) 0x75, (byte) 0xfa, (byte) 0x9f, (byte) 0xd2,
            (byte) 0x05, (byte) 0xed, (byte) 0x48, (byte) 0xfc,
            (byte) 0x4e, (byte) 0x30, (byte) 0x99, (byte) 0xcb,
            (byte) 0xb1, (byte) 0xd6, (byte) 0xed, (byte) 0x03,
            (byte) 0x1b, (byte) 0x7d, (byte) 0xdb, (byte) 0xff,
            (byte) 0x1d, (byte) 0x63, (byte) 0x4e, (byte) 0xb9,
            (byte) 0x7a, (byte) 0x83, (byte) 0xd9, (byte) 0xb7,
            (byte) 0x80, (byte) 0xcf, (byte) 0xd4, (byte) 0xde,
            (byte) 0xdf, (byte) 0xdd, (byte) 0x2c, (byte) 0x76,
            (byte) 0x04, (byte) 0xd1, (byte) 0x43, (byte) 0x19,
            (byte) 0x6c, (byte) 0x08, (byte) 0xd9, (byte) 0x33
    };

    public static final byte[] ECSP384_FP_R = {
            (byte) 0xd0, (byte) 0xdf, (byte) 0x6c, (byte) 0x96,
            (byte) 0xcf, (byte) 0xf7, (byte) 0x08, (byte) 0x1b,
            (byte) 0xe8, (byte) 0x0d, (byte) 0x22, (byte) 0xb0,
            (byte) 0x05, (byte) 0x75, (byte) 0x8a, (byte) 0x2e,
            (byte) 0x2f, (byte) 0x04, (byte) 0x6e, (byte) 0x15,
            (byte) 0xfe, (byte) 0x02, (byte) 0x0e, (byte) 0xf7,
            (byte) 0x66, (byte) 0x4e, (byte) 0xd5, (byte) 0x1d,
            (byte) 0x77, (byte) 0x01, (byte) 0xc8, (byte) 0x6b,
            (byte) 0xf2, (byte) 0xa1, (byte) 0xe9, (byte) 0xf3,
            (byte) 0x00, (byte) 0x2c, (byte) 0x26, (byte) 0xfe,
            (byte) 0x00, (byte) 0x23, (byte) 0x14, (byte) 0xc3,
            (byte) 0xc9, (byte) 0x2f, (byte) 0x1c, (byte) 0xa9
    };

    public static final short ECSP384_FP_K = 1;

    public static final byte[] ECSP384_FP_W_X = {
            (byte) 0xa4, (byte) 0xbd, (byte) 0x57, (byte) 0x5b,
            (byte) 0xf2, (byte) 0x03, (byte) 0x00, (byte) 0xb0,
            (byte) 0xcf, (byte) 0x8a, (byte) 0x2f, (byte) 0x41,
            (byte) 0xdd, (byte) 0x5a, (byte) 0x03, (byte) 0xe9,
            (byte) 0x08, (byte) 0x96, (byte) 0x6a, (byte) 0x42,
            (byte) 0x29, (byte) 0xa5, (byte) 0xf2, (byte) 0x2f,
            (byte) 0x5c, (byte) 0x19, (byte) 0x0d, (byte) 0x36,
            (byte) 0x41, (byte) 0xac, (byte) 0x2d, (byte) 0x32,
            (byte) 0xb7, (byte) 0xb2, (byte) 0x4a, (byte) 0x63,
            (byte) 0x48, (byte) 0x2c, (byte) 0xbb, (byte) 0xcd,
            (byte) 0x0c, (byte) 0x22, (byte) 0x57, (byte) 0xf8,
            (byte) 0x34, (byte) 0x83, (byte) 0x4e, (byte) 0xf1
    };

    public static final byte[] ECSP384_FP_W_Y = {
            (byte) 0x38, (byte) 0xd5, (byte) 0x1c, (byte) 0x8f,
            (byte) 0x9e, (byte) 0x90, (byte) 0x59, (byte) 0x2f,
            (byte) 0x56, (byte) 0x7e, (byte) 0x81, (byte) 0xd0,
            (byte) 0xe4, (byte) 0x85, (byte) 0x5e, (byte) 0x79,
            (byte) 0x73, (byte) 0x1b, (byte) 0x57, (byte) 0x97,
            (byte) 0x85, (byte) 0x7a, (byte) 0x4c, (byte) 0x7d,
            (byte) 0xc2, (byte) 0x70, (byte) 0x65, (byte) 0x3b,
            (byte) 0xc9, (byte) 0xf0, (byte) 0xc3, (byte) 0x1e,
            (byte) 0x84, (byte) 0x69, (byte) 0x30, (byte) 0x07,
            (byte) 0xb0, (byte) 0x9c, (byte) 0xeb, (byte) 0xf7,
            (byte) 0x10, (byte) 0xd5, (byte) 0xae, (byte) 0x32,
            (byte) 0x37, (byte) 0x30, (byte) 0x39, (byte) 0x49
    };


    //Anomalous curve(small-pub-521), with pubkey of order 4
    public static final byte[] ECSP521_FP_P = {
            (byte) 0x01, (byte) 0x9f, (byte) 0x9b, (byte) 0x18,
            (byte) 0x84, (byte) 0x55, (byte) 0xfc, (byte) 0xb2,
            (byte) 0x4e, (byte) 0x68, (byte) 0xee, (byte) 0xba,
            (byte) 0xbf, (byte) 0x2a, (byte) 0xfd, (byte) 0xa0,
            (byte) 0xb5, (byte) 0x11, (byte) 0x4e, (byte) 0xc5,
            (byte) 0xe8, (byte) 0x2b, (byte) 0x6d, (byte) 0xa1,
            (byte) 0x8f, (byte) 0xa2, (byte) 0x64, (byte) 0x31,
            (byte) 0xee, (byte) 0x72, (byte) 0x03, (byte) 0xa2,
            (byte) 0x3d, (byte) 0x8b, (byte) 0xd7, (byte) 0xc4,
            (byte) 0x16, (byte) 0x9b, (byte) 0x73, (byte) 0x0d,
            (byte) 0xbc, (byte) 0x9c, (byte) 0xff, (byte) 0xd8,
            (byte) 0xc0, (byte) 0xe7, (byte) 0x9d, (byte) 0xc4,
            (byte) 0x03, (byte) 0x74, (byte) 0x12, (byte) 0x8d,
            (byte) 0xeb, (byte) 0x03, (byte) 0x44, (byte) 0x56,
            (byte) 0x96, (byte) 0x0b, (byte) 0x87, (byte) 0x3d,
            (byte) 0xfd, (byte) 0x26, (byte) 0x2b, (byte) 0xe0,
            (byte) 0xb6, (byte) 0xd5
    };

    public static final byte[] ECSP521_FP_A = {
            (byte) 0x8e,   (byte) 0xdc,   (byte) 0x39,   (byte) 0xcd,
            (byte) 0xdd,   (byte) 0x0f,   (byte) 0x31,   (byte) 0x73,
            (byte) 0x71,   (byte) 0x67,   (byte) 0x46,   (byte) 0xac,
            (byte) 0x53,   (byte) 0x94,   (byte) 0xb6,   (byte) 0x1e,
            (byte) 0x11,   (byte) 0xc0,   (byte) 0x56,   (byte) 0x67,
            (byte) 0xec,   (byte) 0xba,   (byte) 0x2f,   (byte) 0x25,
            (byte) 0x05,   (byte) 0xb7,   (byte) 0x28,   (byte) 0x6c,
            (byte) 0x5b,   (byte) 0xab,   (byte) 0x09,   (byte) 0x02,
            (byte) 0x09,   (byte) 0x1d,   (byte) 0xf8,   (byte) 0xa6,
            (byte) 0xbe,   (byte) 0x38,   (byte) 0xcd,   (byte) 0x4a,
            (byte) 0x45,   (byte) 0xa8,   (byte) 0x17,   (byte) 0xad,
            (byte) 0x2a,   (byte) 0xfd,   (byte) 0x57,   (byte) 0x6f,
            (byte) 0xdc,   (byte) 0xbd,   (byte) 0x2f,   (byte) 0x27,
            (byte) 0x01,   (byte) 0xc4,   (byte) 0x5e,   (byte) 0xae,
            (byte) 0x1a,   (byte) 0x55,   (byte) 0x88,   (byte) 0xee,
            (byte) 0xc7,   (byte) 0xd1,   (byte) 0x08,   (byte) 0x42,
            (byte) 0x3d
    };

    public static final byte[] ECSP521_FP_B = {
            (byte) 0x2d,   (byte) 0x83,   (byte) 0x7c,   (byte) 0xac,
            (byte) 0x89,   (byte) 0x02,   (byte) 0xfe,   (byte) 0x65,
            (byte) 0x1e,   (byte) 0x81,   (byte) 0x7f,   (byte) 0x20,
            (byte) 0x6d,   (byte) 0x5c,   (byte) 0x9e,   (byte) 0xb7,
            (byte) 0x8a,   (byte) 0xed,   (byte) 0xef,   (byte) 0x80,
            (byte) 0xd1,   (byte) 0x6e,   (byte) 0xa1,   (byte) 0x67,
            (byte) 0xbb,   (byte) 0x37,   (byte) 0x7c,   (byte) 0xb7,
            (byte) 0xff,   (byte) 0xfc,   (byte) 0x0c,   (byte) 0x94,
            (byte) 0x8e,   (byte) 0xef,   (byte) 0xea,   (byte) 0x5f,
            (byte) 0xd3,   (byte) 0x46,   (byte) 0xfe,   (byte) 0x4c,
            (byte) 0x82,   (byte) 0xa1,   (byte) 0x6d,   (byte) 0x1a,
            (byte) 0x46,   (byte) 0xb8,   (byte) 0xeb,   (byte) 0x05,
            (byte) 0xe5,   (byte) 0x70,   (byte) 0xcb,   (byte) 0x76,
            (byte) 0xe7,   (byte) 0x1d,   (byte) 0xb0,   (byte) 0xad,
            (byte) 0xc1,   (byte) 0x99,   (byte) 0xbd,   (byte) 0xe2,
            (byte) 0x83,   (byte) 0x4a,   (byte) 0xd6,   (byte) 0x74,
            (byte) 0x1f
    };

    public static final byte[] ECSP521_FP_G_X = {
            (byte) 0xe5,   (byte) 0xa6,   (byte) 0x65,   (byte) 0xfc,
            (byte) 0x52,   (byte) 0x93,   (byte) 0xfa,   (byte) 0xd7,
            (byte) 0x05,   (byte) 0x0f,   (byte) 0x63,   (byte) 0x31,
            (byte) 0x18,   (byte) 0xfb,   (byte) 0x91,   (byte) 0x55,
            (byte) 0x23,   (byte) 0x85,   (byte) 0x71,   (byte) 0xc8,
            (byte) 0x17,   (byte) 0xe6,   (byte) 0x62,   (byte) 0x6c,
            (byte) 0xe5,   (byte) 0x8e,   (byte) 0x1c,   (byte) 0xb5,
            (byte) 0x11,   (byte) 0x79,   (byte) 0x3d,   (byte) 0x03,
            (byte) 0xab,   (byte) 0x2e,   (byte) 0x18,   (byte) 0x0a,
            (byte) 0x5d,   (byte) 0xaf,   (byte) 0xf4,   (byte) 0x9c,
            (byte) 0xfb,   (byte) 0xb1,   (byte) 0xf8,   (byte) 0x88,
            (byte) 0xc7,   (byte) 0xd8,   (byte) 0x06,   (byte) 0x9a,
            (byte) 0x60,   (byte) 0xcd,   (byte) 0x09,   (byte) 0xcc,
            (byte) 0x6a,   (byte) 0xfc,   (byte) 0x2b,   (byte) 0x6b,
            (byte) 0xb1,   (byte) 0xea,   (byte) 0x54,   (byte) 0xea,
            (byte) 0x98,   (byte) 0x5e,   (byte) 0x78,   (byte) 0xd3,
            (byte) 0x1f
    };

    public static final byte[] ECSP521_FP_G_Y = {
            (byte) 0x01,   (byte) 0x06,   (byte) 0x7b,   (byte) 0x42,
            (byte) 0x85,   (byte) 0x9e,   (byte) 0x5c,   (byte) 0x33,
            (byte) 0x98,   (byte) 0xab,   (byte) 0xa9,   (byte) 0xec,
            (byte) 0xc0,   (byte) 0x2b,   (byte) 0xf2,   (byte) 0x89,
            (byte) 0xf9,   (byte) 0xe3,   (byte) 0x13,   (byte) 0x37,
            (byte) 0x1e,   (byte) 0x70,   (byte) 0x21,   (byte) 0xbf,
            (byte) 0x1d,   (byte) 0xb5,   (byte) 0xae,   (byte) 0xbe,
            (byte) 0x2d,   (byte) 0x52,   (byte) 0x9e,   (byte) 0x2f,
            (byte) 0x66,   (byte) 0x23,   (byte) 0xa0,   (byte) 0x6f,
            (byte) 0x3b,   (byte) 0x10,   (byte) 0xe7,   (byte) 0xf9,
            (byte) 0x2c,   (byte) 0x3e,   (byte) 0xcc,   (byte) 0x18,
            (byte) 0x3d,   (byte) 0xe1,   (byte) 0xe5,   (byte) 0x91,
            (byte) 0x9b,   (byte) 0x0d,   (byte) 0x6d,   (byte) 0x2e,
            (byte) 0xd6,   (byte) 0x55,   (byte) 0xec,   (byte) 0x31,
            (byte) 0xc3,   (byte) 0x13,   (byte) 0x15,   (byte) 0x9f,
            (byte) 0x2c,   (byte) 0x9d,   (byte) 0xf9,   (byte) 0x15,
            (byte) 0xfb,   (byte) 0xe0
    };

    public static final byte[] ECSP521_FP_R = {
            (byte) 0x01,   (byte) 0x9f,   (byte) 0x9b,   (byte) 0x18,
            (byte) 0x84,   (byte) 0x55,   (byte) 0xfc,   (byte) 0xb2,
            (byte) 0x4e,   (byte) 0x68,   (byte) 0xee,   (byte) 0xba,
            (byte) 0xbf,   (byte) 0x2a,   (byte) 0xfd,   (byte) 0xa0,
            (byte) 0xb5,   (byte) 0x11,   (byte) 0x4e,   (byte) 0xc5,
            (byte) 0xe8,   (byte) 0x2b,   (byte) 0x6d,   (byte) 0xa1,
            (byte) 0x8f,   (byte) 0xa2,   (byte) 0x64,   (byte) 0x31,
            (byte) 0xee,   (byte) 0x72,   (byte) 0x03,   (byte) 0xa2,
            (byte) 0x3d,   (byte) 0x75,   (byte) 0xdd,   (byte) 0xed,
            (byte) 0x80,   (byte) 0x28,   (byte) 0x58,   (byte) 0xff,
            (byte) 0xab,   (byte) 0x06,   (byte) 0x8f,   (byte) 0x74,
            (byte) 0xf8,   (byte) 0x9c,   (byte) 0xc7,   (byte) 0x73,
            (byte) 0x85,   (byte) 0x0e,   (byte) 0x1b,   (byte) 0x56,
            (byte) 0x84,   (byte) 0x3f,   (byte) 0x76,   (byte) 0x7c,
            (byte) 0x15,   (byte) 0xef,   (byte) 0x65,   (byte) 0xb4,
            (byte) 0x12,   (byte) 0xe6,   (byte) 0x50,   (byte) 0xc9,
            (byte) 0x7b,   (byte) 0xd0
    };

    public static final short ECSP521_FP_K = 1;

    public static final byte[] ECSP521_FP_W_X = {
            (byte) 0xfc,   (byte) 0xcf,   (byte) 0x5c,   (byte) 0x11,
            (byte) 0x3b,   (byte) 0xec,   (byte) 0x94,   (byte) 0x61,
            (byte) 0xdb,   (byte) 0x3e,   (byte) 0x56,   (byte) 0x73,
            (byte) 0x34,   (byte) 0xcb,   (byte) 0xf9,   (byte) 0x8e,
            (byte) 0x32,   (byte) 0xde,   (byte) 0x58,   (byte) 0x12,
            (byte) 0x92,   (byte) 0x07,   (byte) 0x74,   (byte) 0xdb,
            (byte) 0x40,   (byte) 0xd2,   (byte) 0x94,   (byte) 0x18,
            (byte) 0xd2,   (byte) 0x92,   (byte) 0xc3,   (byte) 0xc4,
            (byte) 0xf6,   (byte) 0xce,   (byte) 0x08,   (byte) 0xb2,
            (byte) 0x00,   (byte) 0x21,   (byte) 0xfe,   (byte) 0x0f,
            (byte) 0x07,   (byte) 0xf0,   (byte) 0xe4,   (byte) 0xc9,
            (byte) 0xc3,   (byte) 0xd1,   (byte) 0x43,   (byte) 0xe7,
            (byte) 0xd0,   (byte) 0xf8,   (byte) 0xcd,   (byte) 0xb6,
            (byte) 0x16,   (byte) 0x71,   (byte) 0xa7,   (byte) 0xe4,
            (byte) 0x46,   (byte) 0x8a,   (byte) 0x93,   (byte) 0xde,
            (byte) 0xe6,   (byte) 0x0c,   (byte) 0x1d,   (byte) 0x29,
            (byte) 0xde
    };

    public static final byte[] ECSP521_FP_W_Y = {
            (byte) 0xc3,   (byte) 0x6d,   (byte) 0x08,   (byte) 0x8f,
            (byte) 0xc2,   (byte) 0xfe,   (byte) 0x3b,   (byte) 0x42,
            (byte) 0x90,   (byte) 0x7b,   (byte) 0xbf,   (byte) 0x8a,
            (byte) 0xf7,   (byte) 0xf1,   (byte) 0x9e,   (byte) 0xda,
            (byte) 0x94,   (byte) 0x82,   (byte) 0x10,   (byte) 0x1d,
            (byte) 0x4f,   (byte) 0x73,   (byte) 0xf8,   (byte) 0xcd,
            (byte) 0x46,   (byte) 0x73,   (byte) 0x6e,   (byte) 0x06,
            (byte) 0x35,   (byte) 0xe1,   (byte) 0xc5,   (byte) 0xca,
            (byte) 0xe1,   (byte) 0x71,   (byte) 0x09,   (byte) 0x30,
            (byte) 0x8c,   (byte) 0x3a,   (byte) 0xec,   (byte) 0x74,
            (byte) 0x10,   (byte) 0xf7,   (byte) 0xec,   (byte) 0x06,
            (byte) 0xfb,   (byte) 0x78,   (byte) 0xec,   (byte) 0xa4,
            (byte) 0xb8,   (byte) 0xcb,   (byte) 0xac,   (byte) 0xb6,
            (byte) 0x4d,   (byte) 0xaf,   (byte) 0x54,   (byte) 0x8f,
            (byte) 0x95,   (byte) 0x02,   (byte) 0xf4,   (byte) 0x87,
            (byte) 0x77,   (byte) 0x53,   (byte) 0xda,   (byte) 0x15,
            (byte) 0x2e
    };


    // getCorruptCurveParameter PARAMETER_CORRUPTION TYPES
    public static final short CORRUPTION_NONE = 0x01;
    public static final short CORRUPTION_FIXED = 0x02;
    public static final short CORRUPTION_FULLRANDOM = 0x03;
    public static final short CORRUPTION_ONEBYTERANDOM = 0x04;
    public static final short CORRUPTION_ZERO = 0x05;
    public static final short CORRUPTION_ONE = 0x06;

    // Supported embedded curves, getCurveParameter
    // SECP recommended curves over FP
    public static final byte CURVE_secp128r1 = 1;
    public static final byte CURVE_secp160r1 = 2;
    public static final byte CURVE_secp192r1 = 3;
    public static final byte CURVE_secp224r1 = 4;
    public static final byte CURVE_secp256r1 = 5;
    public static final byte CURVE_secp384r1 = 6;
    public static final byte CURVE_secp521r1 = 7;

    public static final byte CURVE_sp128 = 8;
    public static final byte CURVE_sp160 = 9;
    public static final byte CURVE_sp192 = 10;
    public static final byte CURVE_sp224 = 11;
    public static final byte CURVE_sp256 = 12;
    public static final byte CURVE_sp384 = 13;
    public static final byte CURVE_sp521 = 14;

    public static final byte FP_CURVES = 14;

    // SECP recommended curves over F2M
    public static final byte CURVE_sect163r1 = 15;
    public static final byte CURVE_sect233r1 = 16;
    public static final byte CURVE_sect283r1 = 17;
    public static final byte CURVE_sect409r1 = 18;
    public static final byte CURVE_sect571r1 = 19;

    public static final byte F2M_CURVES = 12;

    public static byte getCurve(short keyClass, short keyLength) {
        if (keyClass == KeyPair.ALG_EC_FP) {
            switch (keyLength) {
                case (short) 128:
                    return CURVE_secp128r1;
                case (short) 160:
                    return CURVE_secp160r1;
                case (short) 192:
                    return CURVE_secp192r1;
                case (short) 224:
                    return CURVE_secp224r1;
                case (short) 256:
                    return CURVE_secp256r1;
                case (short) 384:
                    return CURVE_secp384r1;
                case (short) 521:
                    return CURVE_secp521r1;
                default:
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
        } else if (keyClass == KeyPair.ALG_EC_F2M) {
            switch (keyLength) {
                case (short) 163:
                    return CURVE_sect163r1;
                case (short) 233:
                    return CURVE_sect233r1;
                case (short) 283:
                    return CURVE_sect283r1;
                case (short) 409:
                    return CURVE_sect409r1;
                case (short) 571:
                    return CURVE_sect571r1;
                default:
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
        } else {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        return 0;
    }

    public static byte getAnomalousCurve(short keyClass, short keyLength) {
        if (keyClass == KeyPair.ALG_EC_FP) {
            switch (keyLength) {
                case (short) 128:
                    return CURVE_sp128;
                case (short) 160:
                    return CURVE_sp160;
                case (short) 192:
                    return CURVE_sp192;
                case (short) 224:
                    return CURVE_sp224;
                case (short) 256:
                    return CURVE_sp256;
                case (short) 384:
                    return CURVE_sp384;
                case (short) 521:
                    return CURVE_sp521;
                default:
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
        } else if (keyClass == KeyPair.ALG_EC_F2M) {
            return 0;
        } else {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        return 0;
    }

    public static short getCurveParameter(byte curve, short param, byte[] outputBuffer, short outputOffset) {
        byte alg = getCurveType(curve);
        switch (curve) {
            case CURVE_secp128r1: {
                EC_FP_P = EC128_FP_P;
                EC_A = EC128_FP_A;
                EC_B = EC128_FP_B;
                EC_G_X = EC128_FP_G_X;
                EC_G_Y = EC128_FP_G_Y;
                EC_R = EC128_FP_R;
                EC_K = EC128_FP_K;
                break;
            }
            case CURVE_secp160r1: {
                EC_FP_P = EC160_FP_P;
                EC_A = EC160_FP_A;
                EC_B = EC160_FP_B;
                EC_G_X = EC160_FP_G_X;
                EC_G_Y = EC160_FP_G_Y;
                EC_R = EC160_FP_R;
                EC_K = EC160_FP_K;
                break;
            }
            case CURVE_secp192r1: {
                EC_FP_P = EC192_FP_P;
                EC_A = EC192_FP_A;
                EC_B = EC192_FP_B;
                EC_G_X = EC192_FP_G_X;
                EC_G_Y = EC192_FP_G_Y;
                EC_R = EC192_FP_R;
                EC_K = EC192_FP_K;
                break;
            }
            case CURVE_secp224r1: {
                EC_FP_P = EC224_FP_P;
                EC_A = EC224_FP_A;
                EC_B = EC224_FP_B;
                EC_G_X = EC224_FP_G_X;
                EC_G_Y = EC224_FP_G_Y;
                EC_R = EC224_FP_R;
                EC_K = EC224_FP_K;
                break;
            }
            case CURVE_secp256r1: {
                EC_FP_P = EC256_FP_P;
                EC_A = EC256_FP_A;
                EC_B = EC256_FP_B;
                EC_G_X = EC256_FP_G_X;
                EC_G_Y = EC256_FP_G_Y;
                EC_R = EC256_FP_R;
                EC_K = EC256_FP_K;
                break;
            }
            case CURVE_secp384r1: {
                EC_FP_P = EC384_FP_P;
                EC_A = EC384_FP_A;
                EC_B = EC384_FP_B;
                EC_G_X = EC384_FP_G_X;
                EC_G_Y = EC384_FP_G_Y;
                EC_R = EC384_FP_R;
                EC_K = EC384_FP_K;
                break;
            }
            case CURVE_secp521r1: {
                EC_FP_P = EC521_FP_P;
                EC_A = EC521_FP_A;
                EC_B = EC521_FP_B;
                EC_G_X = EC521_FP_G_X;
                EC_G_Y = EC521_FP_G_Y;
                EC_R = EC521_FP_R;
                EC_K = EC521_FP_K;
                break;
            }
            case CURVE_sect163r1: {
                EC_F2M_F2M = EC163_F2M_F;
                EC_A = EC163_F2M_A;
                EC_B = EC163_F2M_B;
                EC_G_X = EC163_F2M_G_X;
                EC_G_Y = EC163_F2M_G_Y;
                EC_R = EC163_F2M_R;
                EC_K = EC163_F2M_K;
                break;
            }
            case CURVE_sect233r1: {
                EC_F2M_F2M = EC233_F2M_F;
                EC_A = EC233_F2M_A;
                EC_B = EC233_F2M_B;
                EC_G_X = EC233_F2M_G_X;
                EC_G_Y = EC233_F2M_G_Y;
                EC_R = EC233_F2M_R;
                EC_K = EC233_F2M_K;
                break;
            }
            case CURVE_sect283r1: {
                EC_F2M_F2M = EC283_F2M_F;
                EC_A = EC283_F2M_A;
                EC_B = EC283_F2M_B;
                EC_G_X = EC283_F2M_G_X;
                EC_G_Y = EC283_F2M_G_Y;
                EC_R = EC283_F2M_R;
                EC_K = EC283_F2M_K;
                break;
            }
            case CURVE_sect409r1: {
                EC_F2M_F2M = EC409_F2M_F;
                EC_A = EC409_F2M_A;
                EC_B = EC409_F2M_B;
                EC_G_X = EC409_F2M_G_X;
                EC_G_Y = EC409_F2M_G_Y;
                EC_R = EC409_F2M_R;
                EC_K = EC409_F2M_K;
                break;
            }
            case CURVE_sect571r1: {
                EC_F2M_F2M = EC571_F2M_F;
                EC_A = EC571_F2M_A;
                EC_B = EC571_F2M_B;
                EC_G_X = EC571_F2M_G_X;
                EC_G_Y = EC571_F2M_G_Y;
                EC_R = EC571_F2M_R;
                EC_K = EC571_F2M_K;
                break;
            }
            case CURVE_sp128: {
                EC_FP_P = ECSP128_FP_P;
                EC_A = ECSP128_FP_A;
                EC_B = ECSP128_FP_B;
                EC_G_X = ECSP128_FP_G_X;
                EC_G_Y = ECSP128_FP_G_Y;
                EC_R = ECSP128_FP_R;
                EC_K = ECSP128_FP_K;
                EC_W_X = ECSP128_FP_W_X;
                EC_W_Y = ECSP128_FP_W_Y;
                break;
            }
            case CURVE_sp160: {
                EC_FP_P = ECSP160_FP_P;
                EC_A = ECSP160_FP_A;
                EC_B = ECSP160_FP_B;
                EC_G_X = ECSP160_FP_G_X;
                EC_G_Y = ECSP160_FP_G_Y;
                EC_R = ECSP160_FP_R;
                EC_K = ECSP160_FP_K;
                EC_W_X = ECSP160_FP_W_X;
                EC_W_Y = ECSP160_FP_W_Y;
                break;
            }
            case CURVE_sp192: {
                EC_FP_P = ECSP192_FP_P;
                EC_A = ECSP192_FP_A;
                EC_B = ECSP192_FP_B;
                EC_G_X = ECSP192_FP_G_X;
                EC_G_Y = ECSP192_FP_G_Y;
                EC_R = ECSP192_FP_R;
                EC_K = ECSP192_FP_K;
                EC_W_X = ECSP192_FP_W_X;
                EC_W_Y = ECSP192_FP_W_Y;
                break;
            }
            case CURVE_sp224: {
                EC_FP_P = ECSP224_FP_P;
                EC_A = ECSP224_FP_A;
                EC_B = ECSP224_FP_B;
                EC_G_X = ECSP224_FP_G_X;
                EC_G_Y = ECSP224_FP_G_Y;
                EC_R = ECSP224_FP_R;
                EC_K = ECSP224_FP_K;
                EC_W_X = ECSP224_FP_W_X;
                EC_W_Y = ECSP224_FP_W_Y;
                break;
            }
            case CURVE_sp256: {
                EC_FP_P = ECSP256_FP_P;
                EC_A = ECSP256_FP_A;
                EC_B = ECSP256_FP_B;
                EC_G_X = ECSP256_FP_G_X;
                EC_G_Y = ECSP256_FP_G_Y;
                EC_R = ECSP256_FP_R;
                EC_K = ECSP256_FP_K;
                EC_W_X = ECSP256_FP_W_X;
                EC_W_Y = ECSP256_FP_W_Y;
                break;
            }
            case CURVE_sp384: {
                EC_FP_P = ECSP384_FP_P;
                EC_A = ECSP384_FP_A;
                EC_B = ECSP384_FP_B;
                EC_G_X = ECSP384_FP_G_X;
                EC_G_Y = ECSP384_FP_G_Y;
                EC_R = ECSP384_FP_R;
                EC_K = ECSP384_FP_K;
                EC_W_X = ECSP384_FP_W_X;
                EC_W_Y = ECSP384_FP_W_Y;
                break;
            }
            case CURVE_sp521: {
                EC_FP_P = ECSP521_FP_P;
                EC_A = ECSP521_FP_A;
                EC_B = ECSP521_FP_B;
                EC_G_X = ECSP521_FP_G_X;
                EC_G_Y = ECSP521_FP_G_Y;
                EC_R = ECSP521_FP_R;
                EC_K = ECSP521_FP_K;
                EC_W_X = ECSP521_FP_W_X;
                EC_W_Y = ECSP521_FP_W_Y;
                break;
            }
            default:
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        short length = 0;
        switch (param) {
            case PARAMETER_FP:
                if (alg == KeyPair.ALG_EC_FP) {
                    length = Util.arrayCopyNonAtomic(EC_FP_P, (short) 0, outputBuffer, outputOffset, (short) EC_FP_P.length);
                }
                break;
            case PARAMETER_F2M:
                if (alg == KeyPair.ALG_EC_F2M) {
                    length = Util.arrayCopyNonAtomic(EC_F2M_F2M, (short) 0, outputBuffer, outputOffset, (short) EC_F2M_F2M.length);
                }
                break;
            case PARAMETER_A:
                length = Util.arrayCopyNonAtomic(EC_A, (short) 0, outputBuffer, outputOffset, (short) EC_A.length);
                break;
            case PARAMETER_B:
                length = Util.arrayCopyNonAtomic(EC_B, (short) 0, outputBuffer, outputOffset, (short) EC_B.length);
                break;
            case PARAMETER_G:
                length = toX962(outputBuffer, outputOffset, EC_G_X, (short) 0, (short) EC_G_X.length, EC_G_Y, (short) 0, (short) EC_G_Y.length);
                break;
            case PARAMETER_R:
                length = Util.arrayCopyNonAtomic(EC_R, (short) 0, outputBuffer, outputOffset, (short) EC_R.length);
                break;
            case PARAMETER_K:
                length = 2;
                Util.setShort(outputBuffer, outputOffset, EC_K);
                break;
            case PARAMETER_W:
                length = toX962(outputBuffer, outputOffset, EC_W_X, (short) 0, (short) EC_W_X.length, EC_W_Y, (short) 0, (short) EC_W_Y.length);
                break;
            case PARAMETER_S:
                length = Util.arrayCopyNonAtomic(EC_S, (short) 0, outputBuffer, outputOffset, (short) EC_S.length);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        return length;
    }

    public static short getCorruptCurveParameter(byte curve, short param, byte[] outputBuffer, short outputOffset, short corruptionType) {
        short length = getCurveParameter(curve, param, outputBuffer, outputOffset);
        if (length <= 0) {
            return length;
        }
        switch (corruptionType) {
            case CORRUPTION_NONE:
                break;
            case CORRUPTION_FIXED:
                if (length >= 1) {
                    outputBuffer[outputOffset] = (byte) 0xcc;
                    outputBuffer[(short) (outputOffset + length - 1)] = (byte) 0xcc;
                }
                break;
            case CORRUPTION_FULLRANDOM:
                m_random.generateData(outputBuffer, outputOffset, length);
                break;
            case CORRUPTION_ONEBYTERANDOM:
                short first = Util.getShort(outputBuffer, (short) 0); // save first two bytes

                m_random.generateData(outputBuffer, (short) 0, (short) 2); // generate position
                short rngPos = Util.getShort(outputBuffer, (short) 0); // save generated position

                Util.setShort(outputBuffer, (short) 0, first); // restore first two bytes

                if (rngPos < 0) { // make positive
                    rngPos = (short) -rngPos;
                }
                rngPos %= length; // make < param length

                byte original = outputBuffer[rngPos];
                do {
                    m_random.generateData(outputBuffer, rngPos, (short) 1);
                } while (original == outputBuffer[rngPos]);
                break;
            case CORRUPTION_ZERO:
                Util.arrayFillNonAtomic(outputBuffer, outputOffset, length, (byte) 0);
                break;
            case CORRUPTION_ONE:
                Util.arrayFillNonAtomic(outputBuffer, outputOffset, length, (byte) 1);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            /* //TODO implement CORRUPT_B_LASTBYTEINCREMENT somehow
                    case CORRUPT_B_LASTBYTEINCREMENT:
                        m_ramArray2[(short) (m_lenB - 1)] += 1;
                        // Make sure its not the valid byte again
                        if (m_ramArray[(short) (m_lenB - 1)] == m_ramArray2[(short) (m_lenB - 1)]) {
                            m_ramArray2[(short) (m_lenB - 1)] += 1; // if yes, increment once more
                        }
                        break;
                }
                */
        }
        return length;
    }

    public static byte getCurveType(byte curve) {
        return curve <= FP_CURVES ? KeyPair.ALG_EC_FP : KeyPair.ALG_EC_F2M;
    }

    private static short toX962(byte[] outputBuffer, short outputOffset, byte[] xBuffer, short xOffset, short xLength, byte[] yBuffer, short yOffset, short yLength) {
        short size = 1;
        size += xLength;
        size += yLength;

        short offset = outputOffset;
        outputBuffer[offset] = 0x04;
        offset += 1;

        offset = Util.arrayCopyNonAtomic(xBuffer, xOffset, outputBuffer, offset, xLength);
        Util.arrayCopyNonAtomic(yBuffer, yOffset, outputBuffer, offset, yLength);
        return size;
    }

}
