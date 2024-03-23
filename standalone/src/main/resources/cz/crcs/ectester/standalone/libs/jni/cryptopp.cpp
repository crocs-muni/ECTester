#include "native.h"

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
#include <sstream>
using std::string;

#include <stdexcept>
using std::runtime_error;

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/config.h"
using CryptoPP::byte;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/sha.h"
using CryptoPP::SHA1;
using CryptoPP::SHA224;
using CryptoPP::SHA256;
using CryptoPP::SHA384;
using CryptoPP::SHA512;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/modarith.h"
using CryptoPP::ModularArithmetic;

#include "cryptopp/gf2n.h"
using CryptoPP::PolynomialMod2;
using CryptoPP::GF2NP;
using CryptoPP::GF2NT;
using CryptoPP::GF2NPP;

#include "cryptopp/eccrypto.h"
using CryptoPP::ECP;
using CryptoPP::EC2N;
using CryptoPP::ECDH;
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::ECDSA;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/oids.h"
using CryptoPP::OID;

#include "cryptopp/dsa.h"
using CryptoPP::DSAConvertSignatureFormat;
using CryptoPP::DSA_DER;
using CryptoPP::DSA_P1363;

// ASN1 is a namespace, not an object
#include "cryptopp/asn.h"
using namespace CryptoPP::ASN1;

#include "cryptopp/integer.h"
using CryptoPP::Integer;


#include "cpp_utils.hpp"
#include "c_timing.h"

static jclass provider_class;
static AutoSeededRandomPool rng;


JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_CryptoppLib_createProvider(JNIEnv *env, jobject self) {
    /* Create the custom provider. */
    jclass local_provider_class = env->FindClass("cz/crcs/ectester/standalone/libs/jni/NativeProvider$Cryptopp");
    provider_class = (jclass) env->NewGlobalRef(local_provider_class);

    jmethodID init = env->GetMethodID(local_provider_class, "<init>", "(Ljava/lang/String;DLjava/lang/String;)V");

    std::string lib_name = "Crypto++";

    int lib_version = CRYPTOPP_VERSION;
    std::string info_str = std::to_string(lib_version);
    std::stringstream ss;
    ss << lib_name << " ";
    ss << info_str[0];
    for (size_t i = 1; i < info_str.size(); ++i) {
        ss << "." << info_str[i];
    }

    jstring name = env->NewStringUTF(lib_name.c_str());
    double version = lib_version / 100;
    jstring info = env->NewStringUTF(ss.str().c_str());

    return env->NewObject(provider_class, init, name, version, info);
}

JNIEXPORT void JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeProvider_00024Cryptopp_setup(JNIEnv *env, jobject self){
    jmethodID provider_put = env->GetMethodID(provider_class, "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");

    add_kpg(env, "ECDH", "CryptoppECDH", self, provider_put);
    add_kpg(env, "ECDSA", "CryptoppECDSA", self, provider_put);
    
    add_ka(env, "ECDH", "CryptoppECDH", self, provider_put);
    
    add_sig(env, "SHA1withECDSA", "CryptoppECDSAwithSHA1", self, provider_put);
    add_sig(env, "SHA224withECDSA", "CryptoppECDSAwithSHA224", self, provider_put);
    add_sig(env, "SHA256withECDSA", "CryptoppECDSAwithSHA256", self, provider_put);
    add_sig(env, "SHA384withECDSA", "CryptoppECDSAwithSHA384", self, provider_put);
    add_sig(env, "SHA512withECDSA", "CryptoppECDSAwithSHA512", self, provider_put);

    init_classes(env, "Cryptopp");
}

template <class EC> static std::vector<OID> get_curve_oids() {
    std::vector<OID> oids;
    OID it = OID();
    do {
        it = DL_GroupParameters_EC<EC>::GetNextRecommendedParametersOID(it);
        if (it == OID()) {
            break;
        }
        oids.push_back(it);
    } while (true);

    return oids;
}

static std::vector<OID> get_all_curve_oids() {
    std::vector<OID> ecp_oids = get_curve_oids<ECP>();
    std::vector<OID> ec2n_oids = get_curve_oids<EC2N>();

    std::vector<OID> all_oids;
    all_oids.insert(all_oids.end(), ecp_oids.begin(), ecp_oids.end());
    all_oids.insert(all_oids.end(), ec2n_oids.begin(), ec2n_oids.end());
    return all_oids;
}

static std::string oid_to_str(const OID &oid) {
    const std::vector<CryptoPP::word32>& oid_values = oid.GetValues();
    std::stringstream ss;
    for (size_t i = 0; i < oid_values.size(); ++i) {
        if(i != 0)
            ss << ".";
        ss << std::to_string(oid_values[i]);
    }
    return ss.str();
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_CryptoppLib_getCurves(JNIEnv *env, jobject self){
    jclass set_class = env->FindClass("java/util/TreeSet");

    jmethodID set_ctr = env->GetMethodID(set_class, "<init>", "()V");
    jmethodID set_add = env->GetMethodID(set_class, "add", "(Ljava/lang/Object;)Z");

    jobject result = env->NewObject(set_class, set_ctr);

    std::vector<OID> all_oids = get_all_curve_oids();

    for (auto oid = all_oids.begin(); oid != all_oids.end(); ++oid) {
        jstring name_str = env->NewStringUTF(oid_to_str(*oid).c_str());
        env->CallBooleanMethod(result, set_add, name_str);
    }

    return result;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Cryptopp_keysizeSupported(JNIEnv *env, jobject self, jint keysize){
    std::vector<OID> ecp_oids = get_curve_oids<ECP>();
    for (auto oid = ecp_oids.begin(); oid != ecp_oids.end(); ++oid) {
        DL_GroupParameters_EC<ECP> group(*oid);
        if (((jint) group.GetCurve().GetField().MaxElementBitLength()) == keysize) {
            return JNI_TRUE;
        }
    }

    std::vector<OID> e2n_oids = get_curve_oids<EC2N>();
    for (auto oid = e2n_oids.begin(); oid != e2n_oids.end(); ++oid) {
        DL_GroupParameters_EC<EC2N> group(*oid);
        if (((jint) group.GetCurve().FieldSize().ConvertToLong()) == keysize) {
            return JNI_TRUE;
        }
    }
    return JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Cryptopp_paramsSupported(JNIEnv *env, jobject self, jobject params){
    if (params == NULL) {
        return JNI_FALSE;
    }

    if (env->IsInstanceOf(params, ec_parameter_spec_class)) {
        // Any custom params should be supported.
        return JNI_TRUE;
    } else if (env->IsInstanceOf(params, ecgen_parameter_spec_class)) {
        // Compare with OIDs I guess?
        jmethodID get_name = env->GetMethodID(ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;");
        jstring name = (jstring) env->CallObjectMethod(params, get_name);
        const char *utf_name = env->GetStringUTFChars(name, NULL);
        std::string str_name(utf_name);
        env->ReleaseStringUTFChars(name, utf_name);

        std::vector<OID> all_oids = get_all_curve_oids();
        for (auto oid = all_oids.begin(); oid != all_oids.end(); ++oid) {
            std::string oid_s = oid_to_str(*oid);
            if (str_name == oid_s) {
                return JNI_TRUE;
            }
        }
    }
    return JNI_FALSE;
}

static Integer integer_from_biginteger(JNIEnv *env, jobject bigint) {
    jmethodID to_byte_array = env->GetMethodID(biginteger_class, "toByteArray", "()[B");

    jbyteArray byte_array = (jbyteArray) env->CallObjectMethod(bigint, to_byte_array);
    jsize byte_length = env->GetArrayLength(byte_array);
    jbyte *byte_data = env->GetByteArrayElements(byte_array, NULL);
    Integer result((byte *) byte_data, (size_t) byte_length);
    env->ReleaseByteArrayElements(byte_array, byte_data, JNI_ABORT);
    return result;
}

static jobject biginteger_from_integer(JNIEnv *env, const Integer &integer) {
    jbyteArray byte_array = (jbyteArray) env->NewByteArray(integer.MinEncodedSize());

    jbyte *bigint_bytes = env->GetByteArrayElements(byte_array, NULL);
    integer.Encode((byte *) bigint_bytes, integer.MinEncodedSize());
    env->ReleaseByteArrayElements(byte_array, bigint_bytes, 0);

    jmethodID biginteger_init = env->GetMethodID(biginteger_class, "<init>", "(I[B)V");
    return env->NewObject(biginteger_class, biginteger_init, (jint) 1, byte_array);
}

static jobject biginteger_from_polmod2(JNIEnv *env, const PolynomialMod2 &polmod) {
    jmethodID biginteger_init = env->GetMethodID(biginteger_class, "<init>", "(I[B)V");

    jbyteArray mod_array = env->NewByteArray(polmod.MinEncodedSize());
    jbyte *mod_data = env->GetByteArrayElements(mod_array, NULL);
    polmod.Encode((byte *) mod_data, polmod.MinEncodedSize());
    env->ReleaseByteArrayElements(mod_array, mod_data, 0);

    return env->NewObject(biginteger_class, biginteger_init, (jint) 1, mod_array);
}

static std::unique_ptr<DL_GroupParameters_EC<ECP>> fp_group_from_params(JNIEnv *env, jobject params) {
    if (env->IsInstanceOf(params, ec_parameter_spec_class)) {
        jmethodID get_curve = env->GetMethodID(ec_parameter_spec_class, "getCurve", "()Ljava/security/spec/EllipticCurve;");
        jobject elliptic_curve = env->CallObjectMethod(params, get_curve);

        jmethodID get_field = env->GetMethodID(elliptic_curve_class, "getField", "()Ljava/security/spec/ECField;");
        jobject field = env->CallObjectMethod(elliptic_curve, get_field);

        if (!env->IsInstanceOf(field, fp_field_class)) {
            return nullptr;
        }

        jmethodID get_a = env->GetMethodID(elliptic_curve_class, "getA", "()Ljava/math/BigInteger;");
        jobject a = env->CallObjectMethod(elliptic_curve, get_a);
        Integer ai = integer_from_biginteger(env, a);

        jmethodID get_b = env->GetMethodID(elliptic_curve_class, "getB", "()Ljava/math/BigInteger;");
        jobject b = env->CallObjectMethod(elliptic_curve, get_b);
        Integer bi = integer_from_biginteger(env, b);

        jmethodID get_g = env->GetMethodID(ec_parameter_spec_class, "getGenerator", "()Ljava/security/spec/ECPoint;");
        jobject g = env->CallObjectMethod(params, get_g);

        jmethodID get_x = env->GetMethodID(point_class, "getAffineX", "()Ljava/math/BigInteger;");
        jobject gx = env->CallObjectMethod(g, get_x);

        jmethodID get_y = env->GetMethodID(point_class, "getAffineY", "()Ljava/math/BigInteger;");
        jobject gy = env->CallObjectMethod(g, get_y);

        jmethodID get_n = env->GetMethodID(ec_parameter_spec_class, "getOrder", "()Ljava/math/BigInteger;");
        jobject n = env->CallObjectMethod(params, get_n);
        Integer ni = integer_from_biginteger(env, n);

        jmethodID get_h = env->GetMethodID(ec_parameter_spec_class, "getCofactor", "()I");
        jint h = env->CallIntMethod(params, get_h);
        Integer hi(h);

        jmethodID get_p = env->GetMethodID(fp_field_class, "getP", "()Ljava/math/BigInteger;");
        jobject p = env->CallObjectMethod(field, get_p);
        Integer pi = integer_from_biginteger(env, p);

        ECP curve(pi, ai, bi);

        Integer gxi = integer_from_biginteger(env, gx);
        Integer gyi = integer_from_biginteger(env, gy);
        ECP::Point g_point(gxi, gyi);

        return std::make_unique<DL_GroupParameters_EC<ECP>>(curve, g_point, ni, hi);
    } else if (env->IsInstanceOf(params, ecgen_parameter_spec_class)) {
        jmethodID get_name = env->GetMethodID(ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;");
        jstring name = (jstring) env->CallObjectMethod(params, get_name);
        const char *utf_name = env->GetStringUTFChars(name, NULL);
        std::string str_name(utf_name);
        env->ReleaseStringUTFChars(name, utf_name);

        std::vector<OID> ecp_oids = get_curve_oids<ECP>();
        for (auto oid = ecp_oids.begin(); oid != ecp_oids.end(); ++oid) {
            std::string oid_s = oid_to_str(*oid);
            if (str_name == oid_s) {
                return std::make_unique<DL_GroupParameters_EC<ECP>>(*oid);
            }
        }
    }

    return nullptr;
}

static std::unique_ptr<DL_GroupParameters_EC<EC2N>> f2m_group_from_params(JNIEnv *env, jobject params) {
    if (env->IsInstanceOf(params, ec_parameter_spec_class)) {
        jmethodID get_curve = env->GetMethodID(ec_parameter_spec_class, "getCurve", "()Ljava/security/spec/EllipticCurve;");
        jobject elliptic_curve = env->CallObjectMethod(params, get_curve);

        jmethodID get_field = env->GetMethodID(elliptic_curve_class, "getField", "()Ljava/security/spec/ECField;");
        jobject field = env->CallObjectMethod(elliptic_curve, get_field);

        if (!env->IsInstanceOf(field, f2m_field_class)) {
            return nullptr;
        }

        jmethodID get_a = env->GetMethodID(elliptic_curve_class, "getA", "()Ljava/math/BigInteger;");
        jobject a = env->CallObjectMethod(elliptic_curve, get_a);
        Integer ai = integer_from_biginteger(env, a);

        jmethodID get_b = env->GetMethodID(elliptic_curve_class, "getB", "()Ljava/math/BigInteger;");
        jobject b = env->CallObjectMethod(elliptic_curve, get_b);
        Integer bi = integer_from_biginteger(env, b);

        jmethodID get_g = env->GetMethodID(ec_parameter_spec_class, "getGenerator", "()Ljava/security/spec/ECPoint;");
        jobject g = env->CallObjectMethod(params, get_g);

        jmethodID get_x = env->GetMethodID(point_class, "getAffineX", "()Ljava/math/BigInteger;");
        jobject gx = env->CallObjectMethod(g, get_x);

        jmethodID get_y = env->GetMethodID(point_class, "getAffineY", "()Ljava/math/BigInteger;");
        jobject gy = env->CallObjectMethod(g, get_y);

        jmethodID get_n = env->GetMethodID(ec_parameter_spec_class, "getOrder", "()Ljava/math/BigInteger;");
        jobject n = env->CallObjectMethod(params, get_n);
        Integer ni = integer_from_biginteger(env, n);

        jmethodID get_h = env->GetMethodID(ec_parameter_spec_class, "getCofactor", "()I");
        jint h = env->CallIntMethod(params, get_h);
        Integer hi(h);

        jmethodID get_midterms = env->GetMethodID(f2m_field_class, "getMidTermsOfReductionPolynomial", "()[I");
        jintArray midterms = (jintArray) env->CallObjectMethod(field, get_midterms);
        jsize midterm_length = env->GetArrayLength(midterms);
        jint *midterm_data = env->GetIntArrayElements(midterms, NULL);

        jmethodID get_m = env->GetMethodID(f2m_field_class, "getM", "()I");
        jint m = env->CallIntMethod(field, get_m);

        std::unique_ptr<GF2NP> base_field;
        if (midterm_length == 1) {
            //trinomial, use GF2NT
            base_field = std::make_unique<GF2NT>((unsigned int) m, (unsigned int) midterm_data[0], 0);
        } else {
            //pentanomial, use GF2NPP
            base_field = std::make_unique<GF2NPP>((unsigned int) m, (unsigned int) midterm_data[0], (unsigned int) midterm_data[1], (unsigned int) midterm_data[2], 0);
        }
        env->ReleaseIntArrayElements(midterms, midterm_data, JNI_ABORT);

        jmethodID to_byte_array = env->GetMethodID(biginteger_class, "toByteArray", "()[B");
        jbyteArray a_array = (jbyteArray) env->CallObjectMethod(a, to_byte_array);
        jsize a_length = env->GetArrayLength(a_array);
        jbyte *a_data = env->GetByteArrayElements(a_array, NULL);

        jbyteArray b_array = (jbyteArray) env->CallObjectMethod(b, to_byte_array);
        jsize b_length = env->GetArrayLength(b_array);
        jbyte *b_data = env->GetByteArrayElements(b_array, NULL);

        EC2N curve(*base_field, EC2N::FieldElement((byte *) a_data, (size_t) a_length), EC2N::FieldElement((byte *) b_data, (size_t) b_length));
        env->ReleaseByteArrayElements(a_array, a_data, JNI_ABORT);
        env->ReleaseByteArrayElements(b_array, b_data, JNI_ABORT);

        jbyteArray gx_array = (jbyteArray) env->CallObjectMethod(gx, to_byte_array);
        jsize gx_length = env->GetArrayLength(gx_array);
        jbyte *gx_data = env->GetByteArrayElements(gx_array, NULL);
        PolynomialMod2 gxm((byte *) gx_data, (size_t) gx_length);
        env->ReleaseByteArrayElements(gx_array, gx_data, JNI_ABORT);

        jbyteArray gy_array = (jbyteArray) env->CallObjectMethod(gy, to_byte_array);
        jsize gy_length = env->GetArrayLength(gy_array);
        jbyte *gy_data = env->GetByteArrayElements(gy_array, NULL);
        PolynomialMod2 gym((byte *) gy_data, (size_t) gy_length);
        env->ReleaseByteArrayElements(gy_array, gy_data, JNI_ABORT);

        EC2N::Point g_point(gxm, gym);

        return std::make_unique<DL_GroupParameters_EC<EC2N>>(curve, g_point, ni, hi);
    } else if (env->IsInstanceOf(params, ecgen_parameter_spec_class)) {
        jmethodID get_name = env->GetMethodID(ecgen_parameter_spec_class, "getName", "()Ljava/lang/String;");
        jstring name = (jstring) env->CallObjectMethod(params, get_name);
        const char *utf_name = env->GetStringUTFChars(name, NULL);
        std::string str_name(utf_name);
        env->ReleaseStringUTFChars(name, utf_name);

        std::vector<OID> e2n_oids = get_curve_oids<EC2N>();
        for (auto oid = e2n_oids.begin(); oid != e2n_oids.end(); ++oid) {
            std::string oid_s = oid_to_str(*oid);
            if (str_name == oid_s) {
                return std::make_unique<DL_GroupParameters_EC<EC2N>>(*oid);
            }
        }
    }
    return nullptr;
}


template <class EC> jobject finish_params(JNIEnv *env, jobject field, jobject a, jobject b, jobject gx, jobject gy, DL_GroupParameters_EC<EC> group) {
    jmethodID point_init = env->GetMethodID(point_class, "<init>", "(Ljava/math/BigInteger;Ljava/math/BigInteger;)V");
    jobject g = env->NewObject(point_class, point_init, gx, gy);

    jmethodID elliptic_curve_init = env->GetMethodID(elliptic_curve_class, "<init>", "(Ljava/security/spec/ECField;Ljava/math/BigInteger;Ljava/math/BigInteger;)V");
    jobject elliptic_curve = env->NewObject(elliptic_curve_class, elliptic_curve_init, field, a, b);

    // Integer GetSubgroupOrder
    // Integer GetCofactor
    jobject order = biginteger_from_integer(env, group.GetSubgroupOrder());
    jint cofactor = (jint) group.GetCofactor().ConvertToLong();

    jmethodID ec_parameter_spec_init = env->GetMethodID(ec_parameter_spec_class, "<init>", "(Ljava/security/spec/EllipticCurve;Ljava/security/spec/ECPoint;Ljava/math/BigInteger;I)V");
    return env->NewObject(ec_parameter_spec_class, ec_parameter_spec_init, elliptic_curve, g, order, cofactor);
}

template <class EC> jobject params_from_group(JNIEnv *env, DL_GroupParameters_EC<EC> group) {
    return NULL;
}

template <> jobject params_from_group<ECP>(JNIEnv *env, DL_GroupParameters_EC<ECP> group) {
    ECP curve = group.GetCurve();
    jmethodID fp_field_init = env->GetMethodID(fp_field_class, "<init>", "(Ljava/math/BigInteger;)V");
    ModularArithmetic mod = curve.GetField();
    jobject p = biginteger_from_integer(env, mod.GetModulus());
    jobject a = biginteger_from_integer(env, curve.GetA());
    jobject b = biginteger_from_integer(env, curve.GetB());

    jobject field = env->NewObject(fp_field_class, fp_field_init, p);

    ECP::Point gp = group.GetBasePrecomputation().GetBase(group.GetGroupPrecomputation());
    jobject gx = biginteger_from_integer(env, gp.x);
    jobject gy = biginteger_from_integer(env, gp.y);
    return finish_params(env, field, a, b, gx, gy, group);
}

template <> jobject params_from_group<EC2N>(JNIEnv *env, DL_GroupParameters_EC<EC2N> group) {
    EC2N curve = group.GetCurve();
    PolynomialMod2 mod = curve.GetField().GetModulus();
    int m = mod.Degree();
    unsigned int coeff_count = mod.CoefficientCount();
    jintArray ks;
    int to_find;
    int found = 0;
    if (coeff_count == 3) {
        //trinomial
        ks = env->NewIntArray(1);
        to_find = 1;
    } else if (coeff_count == 5) {
        //pentanomial
        ks = env->NewIntArray(3);
        to_find = 3;
    } else {
        return NULL;
    }
    jint *ks_data = env->GetIntArrayElements(ks, NULL);
    for (int i = m - 1; i > 0 && found < to_find; --i) {
        if (mod.GetCoefficient(i) == 1) {
            ks_data[found++] = i;
        }
    }
    env->ReleaseIntArrayElements(ks, ks_data, 0);

    jmethodID f2m_field_init = env->GetMethodID(f2m_field_class, "<init>", "(I[I)V");
    jobject field = env->NewObject(f2m_field_class, f2m_field_init, (jint) m, ks);

    jobject a = biginteger_from_polmod2(env, curve.GetA());
    jobject b = biginteger_from_polmod2(env, curve.GetB());

    EC2N::Point gp = group.GetBasePrecomputation().GetBase(group.GetGroupPrecomputation());
    jobject gx = biginteger_from_polmod2(env, gp.x);
    jobject gy = biginteger_from_polmod2(env, gp.y);
    return finish_params(env, field, a, b, gx, gy, group);
}

template <class EC> jobject generate_from_group(JNIEnv *env, DL_GroupParameters_EC<EC> group, jobject params) {
    typename ECDH<EC>::Domain ec_domain(group);
    SecByteBlock priv(ec_domain.PrivateKeyLength()), pub(ec_domain.PublicKeyLength());

    try {
        native_timing_start();
        ec_domain.GenerateKeyPair(rng, priv, pub);
        native_timing_stop();
    } catch (Exception & ex) {
        throw_new(env, "java/security/GeneralSecurityException", ex.what());
        return NULL;
    }

    jbyteArray pub_bytearray = env->NewByteArray(pub.SizeInBytes());
    jbyte *pub_bytes = env->GetByteArrayElements(pub_bytearray, NULL);
    std::copy(pub.BytePtr(), pub.BytePtr()+pub.SizeInBytes(), pub_bytes);
    env->ReleaseByteArrayElements(pub_bytearray, pub_bytes, 0);

    jobject ec_pub_param_spec = env->NewLocalRef(params);
    jmethodID ec_pub_init = env->GetMethodID(pubkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject pubkey = env->NewObject(pubkey_class, ec_pub_init, pub_bytearray, ec_pub_param_spec);

    jbyteArray priv_bytearray = env->NewByteArray(priv.SizeInBytes());
    jbyte *priv_bytes = env->GetByteArrayElements(priv_bytearray, NULL);
    std::copy(priv.BytePtr(), priv.BytePtr()+priv.SizeInBytes(), priv_bytes);
    env->ReleaseByteArrayElements(priv_bytearray, priv_bytes, 0);

    jobject ec_priv_param_spec = env->NewLocalRef(params);
    jmethodID ec_priv_init = env->GetMethodID(privkey_class, "<init>", "([BLjava/security/spec/ECParameterSpec;)V");
    jobject privkey = env->NewObject(privkey_class, ec_priv_init, priv_bytearray, ec_priv_param_spec);

    jmethodID keypair_init = env->GetMethodID(keypair_class, "<init>", "(Ljava/security/PublicKey;Ljava/security/PrivateKey;)V");

    return env->NewObject(keypair_class, keypair_init, pubkey, privkey);
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Cryptopp_generate__ILjava_security_SecureRandom_2(JNIEnv *env, jobject self, jint keysize, jobject random){
    std::vector<OID> ecp_oids = get_curve_oids<ECP>();
    for (auto oid = ecp_oids.begin(); oid != ecp_oids.end(); ++oid) {
        DL_GroupParameters_EC<ECP> group(*oid);
        if (((jint) group.GetCurve().GetField().MaxElementBitLength()) == keysize) {
            jobject params = params_from_group(env, group);
            return generate_from_group<ECP>(env, group, params);
        }
    }

    std::vector<OID> e2n_oids = get_curve_oids<EC2N>();
    for (auto oid = e2n_oids.begin(); oid != e2n_oids.end(); ++oid) {
        DL_GroupParameters_EC<EC2N> group(*oid);
        if ((jint) group.GetCurve().FieldSize().ConvertToLong() == keysize) {
            jobject params = params_from_group(env, group);
            return generate_from_group<EC2N>(env, group, params);
        }
    }
    return NULL;
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyPairGeneratorSpi_00024Cryptopp_generate__Ljava_security_spec_AlgorithmParameterSpec_2Ljava_security_SecureRandom_2(JNIEnv *env, jobject self, jobject params, jobject random) {
    std::unique_ptr<DL_GroupParameters_EC<ECP>> ecp_group = fp_group_from_params(env, params);
    if (ecp_group == nullptr) {
        std::unique_ptr<DL_GroupParameters_EC<EC2N>> ec2n_group = f2m_group_from_params(env, params);
        return generate_from_group<EC2N>(env, *ec2n_group, params);
    } else {
        return generate_from_group<ECP>(env, *ecp_group, params);
    }
    return NULL;
}

JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024Cryptopp_generateSecret___3B_3BLjava_security_spec_ECParameterSpec_2(JNIEnv *env, jobject self, jbyteArray pubkey, jbyteArray privkey, jobject params) {
    jsize privkey_length = env->GetArrayLength(privkey);
    jbyte *privkey_data = env->GetByteArrayElements(privkey, NULL);
    SecByteBlock private_key((byte *) privkey_data, privkey_length);
    env->ReleaseByteArrayElements(privkey, privkey_data, JNI_ABORT);

    jsize pubkey_length = env->GetArrayLength(pubkey);
    jbyte *pubkey_data = env->GetByteArrayElements(pubkey, NULL);
    SecByteBlock public_key((byte *) pubkey_data, pubkey_length);
    env->ReleaseByteArrayElements(pubkey, pubkey_data, JNI_ABORT);

    bool success;
    std::unique_ptr<SecByteBlock> secret;
    std::unique_ptr<DL_GroupParameters_EC<ECP>> ecp_group = fp_group_from_params(env, params);
    if (ecp_group == nullptr) {
        std::unique_ptr<DL_GroupParameters_EC<EC2N>> ec2n_group = f2m_group_from_params(env, params);
        ECDH<EC2N>::Domain dh_agreement(*ec2n_group);

        try {
            secret = std::make_unique<SecByteBlock>(dh_agreement.AgreedValueLength());
            native_timing_start();
            success = dh_agreement.Agree(*secret, private_key, public_key);
            native_timing_stop();
        } catch (Exception & ex) {
            throw_new(env, "java/security/GeneralSecurityException", ex.what());
            return NULL;
        }
    } else {
        ECDH<ECP>::Domain dh_agreement(*ecp_group);

        try {
            secret = std::make_unique<SecByteBlock>(dh_agreement.AgreedValueLength());
            native_timing_start();
            success = dh_agreement.Agree(*secret, private_key, public_key);
            native_timing_stop();
        } catch (Exception & ex) {
            throw_new(env, "java/security/GeneralSecurityException", ex.what());
            return NULL;
        }
    }
    if (!success) {
        throw_new(env, "java/security/GeneralSecurityException", "Agreement was unsuccessful.");
        return NULL;
    }

    jbyteArray result = env->NewByteArray(secret->size());
    jbyte *result_data = env->GetByteArrayElements(result, NULL);
    std::copy(secret->begin(), secret->end(), result_data);
    env->ReleaseByteArrayElements(result, result_data, 0);

    return result;
}

JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeKeyAgreementSpi_00024Cryptopp_generateSecret___3B_3BLjava_security_spec_ECParameterSpec_2Ljava_lang_String_2(JNIEnv *env, jobject self, jbyteArray pubkey, jbyteArray privkey, jobject params, jstring algorithm){
    throw_new(env, "java/lang/UnsupportedOperationException", "Not supported.");
    return NULL;
}

template <class EC, class H>
jbyteArray sign_message(JNIEnv *env, DL_GroupParameters_EC<EC> group, jbyteArray data, const Integer & private_key_x) {

    typename ECDSA<EC, H>::PrivateKey pkey;
    pkey.Initialize(group, private_key_x);
    typename ECDSA<EC, H>::Signer signer(pkey);

    std::string signature(signer.MaxSignatureLength(), 0);

    jsize data_length = env->GetArrayLength(data);
    jbyte *data_bytes = env->GetByteArrayElements(data, NULL);
    native_timing_start();
    size_t len = signer.SignMessage(rng, (byte *)data_bytes, data_length, (byte *)signature.c_str());
    native_timing_stop();
    env->ReleaseByteArrayElements(data, data_bytes, JNI_ABORT);
    signature.resize(len);

    byte sig[4096];
    size_t sig_len = DSAConvertSignatureFormat(sig, sizeof(sig), DSA_DER, (byte *)signature.c_str(), len, DSA_P1363);

    jbyteArray result = env->NewByteArray(sig_len);
    jbyte *result_bytes = env->GetByteArrayElements(result, NULL);
    std::copy(sig, sig+sig_len, result_bytes);
    env->ReleaseByteArrayElements(result, result_bytes, 0);

    return result;
}

JNIEXPORT jbyteArray JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024Cryptopp_sign(JNIEnv *env, jobject self, jbyteArray data, jbyteArray privkey, jobject params) {
    jclass cryptopp_sig_class = env->FindClass("cz/crcs/ectester/standalone/libs/jni/NativeSignatureSpi$Cryptopp");
    jfieldID type_id = env->GetFieldID(cryptopp_sig_class, "type", "Ljava/lang/String;");
    jstring type = (jstring) env->GetObjectField(self, type_id);
    const char *type_data = env->GetStringUTFChars(type, NULL);
    std::string type_str(type_data);
    env->ReleaseStringUTFChars(type, type_data);

    jsize privkey_length = env->GetArrayLength(privkey);
    jbyte *privkey_data = env->GetByteArrayElements(privkey, NULL);
    Integer private_key_x((byte *) privkey_data, (size_t) privkey_length);
    env->ReleaseByteArrayElements(privkey, privkey_data, JNI_ABORT);

    jbyteArray result = NULL;

    std::unique_ptr<DL_GroupParameters_EC<ECP>> ecp_group = fp_group_from_params(env, params);
    if (ecp_group == nullptr) {
        std::unique_ptr<DL_GroupParameters_EC<EC2N>> ec2n_group = f2m_group_from_params(env, params);
        if (type_str.find("SHA1") != std::string::npos) {
            result = sign_message<EC2N, SHA1>(env, *ec2n_group, data, private_key_x);
        } else if (type_str.find("SHA224") != std::string::npos) {
            result = sign_message<EC2N, SHA224>(env, *ec2n_group, data, private_key_x);
        } else if (type_str.find("SHA256") != std::string::npos) {
            result = sign_message<EC2N, SHA256>(env, *ec2n_group, data, private_key_x);
        } else if (type_str.find("SHA384") != std::string::npos) {
            result = sign_message<EC2N, SHA384>(env, *ec2n_group, data, private_key_x);
        } else if (type_str.find("SHA512") != std::string::npos) {
            result = sign_message<EC2N, SHA512>(env, *ec2n_group, data, private_key_x);
        }
    } else {
        if (type_str.find("SHA1") != std::string::npos) {
            result = sign_message<ECP, SHA1>(env, *ecp_group, data, private_key_x);
        } else if (type_str.find("SHA224") != std::string::npos) {
            result = sign_message<ECP, SHA224>(env, *ecp_group, data, private_key_x);
        } else if (type_str.find("SHA256") != std::string::npos) {
            result = sign_message<ECP, SHA256>(env, *ecp_group, data, private_key_x);
        } else if (type_str.find("SHA384") != std::string::npos) {
            result = sign_message<ECP, SHA384>(env, *ecp_group, data, private_key_x);
        } else if (type_str.find("SHA512") != std::string::npos) {
            result = sign_message<ECP, SHA512>(env, *ecp_group, data, private_key_x);
        }
    }

    return result;
}

template <class EC, class H>
jboolean verify_message(JNIEnv *env, DL_GroupParameters_EC<EC> group, jbyteArray data, jbyteArray signature, jbyteArray pubkey) {
    typename EC::Point pkey_point;
    jsize pubkey_length = env->GetArrayLength(pubkey);
    jbyte *pubkey_data = env->GetByteArrayElements(pubkey, NULL);
    group.GetCurve().DecodePoint(pkey_point, (byte *)pubkey_data, pubkey_length);
    env->ReleaseByteArrayElements(pubkey, pubkey_data, JNI_ABORT);

    typename ECDSA<EC, H>::PublicKey pkey;
    pkey.Initialize(group, pkey_point);
    typename ECDSA<EC, H>::Verifier verifier(pkey);

    size_t bit_length = group.GetCurve().GetField().MaxElementBitLength();
    size_t bytes = (bit_length + 7)/8;

    jsize sig_length = env->GetArrayLength(signature);
    jbyte *sig_bytes = env->GetByteArrayElements(signature, NULL);

    byte sig[bytes * 2];
    size_t sig_len = DSAConvertSignatureFormat(sig, bytes * 2, DSA_P1363, (byte *)sig_bytes, sig_length, DSA_DER);
    env->ReleaseByteArrayElements(signature, sig_bytes, JNI_ABORT);

    jsize data_length = env->GetArrayLength(data);
    jbyte *data_bytes = env->GetByteArrayElements(data, NULL);
    native_timing_start();
    bool result = verifier.VerifyMessage((byte *)data_bytes, data_length, sig, sig_len);
    native_timing_stop();
    env->ReleaseByteArrayElements(data, data_bytes, JNI_ABORT);

    return result;
}

JNIEXPORT jboolean JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeSignatureSpi_00024Cryptopp_verify(JNIEnv *env, jobject self, jbyteArray signature, jbyteArray data, jbyteArray pubkey, jobject params) {
    jclass cryptopp_sig_class = env->FindClass("cz/crcs/ectester/standalone/libs/jni/NativeSignatureSpi$Cryptopp");
    jfieldID type_id = env->GetFieldID(cryptopp_sig_class, "type", "Ljava/lang/String;");
    jstring type = (jstring) env->GetObjectField(self, type_id);
    const char *type_data = env->GetStringUTFChars(type, NULL);
    std::string type_str(type_data);
    env->ReleaseStringUTFChars(type, type_data);

    std::unique_ptr<DL_GroupParameters_EC<ECP>> ecp_group = fp_group_from_params(env, params);
    if (ecp_group == nullptr) {
        std::unique_ptr<DL_GroupParameters_EC<EC2N>> ec2n_group = f2m_group_from_params(env, params);

        if (type_str.find("SHA1") != std::string::npos) {
            return verify_message<EC2N, SHA1>(env, *ec2n_group, data, signature, pubkey);
        } else if (type_str.find("SHA224") != std::string::npos) {
            return verify_message<EC2N, SHA224>(env, *ec2n_group, data, signature, pubkey);
        } else if (type_str.find("SHA256") != std::string::npos) {
            return verify_message<EC2N, SHA256>(env, *ec2n_group, data, signature, pubkey);
        } else if (type_str.find("SHA384") != std::string::npos) {
            return verify_message<EC2N, SHA384>(env, *ec2n_group, data, signature, pubkey);
        } else if (type_str.find("SHA512") != std::string::npos) {
            return verify_message<EC2N, SHA512>(env, *ec2n_group, data, signature, pubkey);
        }
    } else {
        if (type_str.find("SHA1") != std::string::npos) {
            return verify_message<ECP, SHA1>(env, *ecp_group, data, signature, pubkey);
        } else if (type_str.find("SHA224") != std::string::npos) {
            return verify_message<ECP, SHA224>(env, *ecp_group, data, signature, pubkey);
        } else if (type_str.find("SHA256") != std::string::npos) {
            return verify_message<ECP, SHA256>(env, *ecp_group, data, signature, pubkey);
        } else if (type_str.find("SHA384") != std::string::npos) {
            return verify_message<ECP, SHA384>(env, *ecp_group, data, signature, pubkey);
        } else if (type_str.find("SHA512") != std::string::npos) {
            return verify_message<ECP, SHA512>(env, *ecp_group, data, signature, pubkey);
        }
    }
    // unreachable
    return JNI_FALSE;
}