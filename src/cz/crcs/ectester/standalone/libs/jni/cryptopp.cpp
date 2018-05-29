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

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::AutoSeededX917RNG;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/eccrypto.h"
using CryptoPP::ECP;
using CryptoPP::ECDH;
using CryptoPP::DL_GroupParameters_EC;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/oids.h"
using CryptoPP::OID;

// ASN1 is a namespace, not an object
#include "cryptopp/asn.h"
using namespace CryptoPP::ASN1;

#include "cryptopp/integer.h"
using CryptoPP::Integer;


#include "cpp_utils.hpp"

static jclass provider_class;


/*
 * Class:     cz_crcs_ectester_standalone_libs_CryptoppLib
 * Method:    createProvider
 * Signature: ()Ljava/security/Provider;
 */
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
    for (int i = 1; i < info_str.size(); ++i) {
        ss << "." << info_str[i];
    }

    jstring name = env->NewStringUTF(lib_name.c_str());
    double version = lib_version / 100;
    jstring info = env->NewStringUTF(ss.str().c_str());

    return env->NewObject(provider_class, init, name, version, info);
}

/*
 * Class:     cz_crcs_ectester_standalone_libs_jni_NativeProvider_Cryptopp
 * Method:    setup
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_cz_crcs_ectester_standalone_libs_jni_NativeProvider_00024Cryptopp_setup(JNIEnv *env, jobject self){
    jmethodID provider_put = env->GetMethodID(provider_class, "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");

    init_classes(env, "Cryptopp");
}

/*
 * Class:     cz_crcs_ectester_standalone_libs_CryptoppLib
 * Method:    getCurves
 * Signature: ()Ljava/util/Set;
 */
JNIEXPORT jobject JNICALL Java_cz_crcs_ectester_standalone_libs_CryptoppLib_getCurves(JNIEnv *env, jobject self){
    jclass set_class = env->FindClass("java/util/TreeSet");

    jmethodID set_ctr = env->GetMethodID(set_class, "<init>", "()V");
    jmethodID set_add = env->GetMethodID(set_class, "add", "(Ljava/lang/Object;)Z");

    jobject result = env->NewObject(set_class, set_ctr);

    OID it = OID();
    do {
        it = DL_GroupParameters_EC<ECP>::GetNextRecommendedParametersOID(it);
        if (it == OID()) {
            break;
        }
        const std::vector<CryptoPP::word32>& oid_values = it.GetValues();
        std::stringstream ss;
        for (size_t i = 0; i < oid_values.size(); ++i) {
            if(i != 0)
                ss << ".";
            ss << std::to_string(oid_values[i]);
        }
        jstring name_str = env->NewStringUTF(ss.str().c_str());
        env->CallBooleanMethod(result, set_add, name_str);
    } while (true);

    return result;
}