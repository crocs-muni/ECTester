#include "cpp_utils.hpp"

jclass ec_parameter_spec_class;
jclass ecgen_parameter_spec_class;
jclass secret_key_spec_class;
jclass pubkey_class;
jclass privkey_class;
jclass keypair_class;
jclass elliptic_curve_class;
jclass fp_field_class;
jclass f2m_field_class;
jclass point_class;
jclass biginteger_class;
jclass illegal_state_exception_class;

void init_classes(JNIEnv *env, std::string lib_name) {
    jclass local_ec_parameter_spec_class = env->FindClass("java/security/spec/ECParameterSpec");
    ec_parameter_spec_class = (jclass) env->NewGlobalRef(local_ec_parameter_spec_class);

    jclass local_ecgen_parameter_spec_class = env->FindClass("java/security/spec/ECGenParameterSpec");
    ecgen_parameter_spec_class = (jclass) env->NewGlobalRef(local_ecgen_parameter_spec_class);

    jclass local_secret_key_spec_class = env->FindClass("javax/crypto/spec/SecretKeySpec");
    secret_key_spec_class = (jclass) env->NewGlobalRef(local_secret_key_spec_class);

    std::string pubkey_class_name("cz/crcs/ectester/standalone/libs/jni/NativeECPublicKey$");
    pubkey_class_name += lib_name;

    jclass local_pubkey_class = env->FindClass(pubkey_class_name.c_str());
    pubkey_class = (jclass) env->NewGlobalRef(local_pubkey_class);

    std::string privkey_class_name("cz/crcs/ectester/standalone/libs/jni/NativeECPrivateKey$");
    privkey_class_name += lib_name;

    jclass local_privkey_class = env->FindClass(privkey_class_name.c_str());
    privkey_class = (jclass) env->NewGlobalRef(local_privkey_class);

    jclass local_keypair_class = env->FindClass("java/security/KeyPair");
    keypair_class = (jclass) env->NewGlobalRef(local_keypair_class);

    jclass local_elliptic_curve_class = env->FindClass("java/security/spec/EllipticCurve");
    elliptic_curve_class = (jclass) env->NewGlobalRef(local_elliptic_curve_class);

    jclass local_fp_field_class = env->FindClass("java/security/spec/ECFieldFp");
    fp_field_class = (jclass) env->NewGlobalRef(local_fp_field_class);

    jclass local_f2m_field_class = env->FindClass("java/security/spec/ECFieldF2m");
    f2m_field_class = (jclass) env->NewGlobalRef(local_f2m_field_class);

    jclass local_biginteger_class = env->FindClass("java/math/BigInteger");
    biginteger_class = (jclass) env->NewGlobalRef(local_biginteger_class);

    jclass local_point_class = env->FindClass("java/security/spec/ECPoint");
    point_class = (jclass) env->NewGlobalRef(local_point_class);

    jclass local_illegal_state_exception_class = env->FindClass("java/lang/IllegalStateException");
    illegal_state_exception_class = (jclass) env->NewGlobalRef(local_illegal_state_exception_class);
}

void throw_new(JNIEnv *env, const std::string& klass, const std::string& message) {
    jclass clazz = env->FindClass(klass.c_str());
    env->ThrowNew(clazz, message.c_str());
}

jint get_kdf_bits(JNIEnv *env, jstring algorithm) {
    if (algorithm == NULL) {
        return 0;
    }

    const char *algo_data = env->GetStringUTFChars(algorithm, NULL);
    std::string algo(algo_data);

    jint result = 0;
    if (algo == "DES") {
        result = 64;
    } else if (algo == "BLOWFISH") {
        result = 128;
    } else if (algo == "DESEDE") {
        result = 192;
    } else if (algo == "AES" || algo == "CAMELLIA") {
        result = 256;
    } else {
        char *end;
        long bits = strtol(algo_data, &end, 10);
        if (*end == 0) {
            result = (jint) bits;
        }
    }
    env->ReleaseStringUTFChars(algorithm, algo_data);
    return result;
}

static void add_provider_property(JNIEnv *env, const std::string &type, const std::string &klass, jobject provider, jmethodID put_method) {
    jstring type_str = env->NewStringUTF(type.c_str());
    jstring class_str = env->NewStringUTF(klass.c_str());
    env->CallObjectMethod(provider, put_method, type_str, class_str);
}

void add_kpg(JNIEnv *env, const std::string &type, const std::string &klass, jobject provider, jmethodID put_method) {
    const std::string full_type = "KeyPairGenerator." + type;
    const std::string full_class = "cz.crcs.ectester.standalone.libs.jni.NativeKeyPairGeneratorSpi$" + klass;
    add_provider_property(env, full_type, full_class, provider, put_method);
}

void add_ka(JNIEnv *env, const std::string &type, const std::string &klass, jobject provider, jmethodID put_method) {
    const std::string full_type = "KeyAgreement." + type;
    const std::string full_class = "cz.crcs.ectester.standalone.libs.jni.NativeKeyAgreementSpi$" + klass;
    add_provider_property(env, full_type, full_class, provider, put_method);
}

void add_sig(JNIEnv *env, const std::string &type, const std::string &klass, jobject provider, jmethodID put_method) {
    const std::string full_type = "Signature." + type;
    const std::string full_class = "cz.crcs.ectester.standalone.libs.jni.NativeSignatureSpi$" + klass;
    add_provider_property(env, full_type, full_class, provider, put_method);
}