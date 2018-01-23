#pragma once

#include "native.h"

/**
 * Classes that are accessed alot are cached here, manually.
 */
extern jclass ec_parameter_spec_class;
extern jclass ecgen_parameter_spec_class;
extern jclass pubkey_class;
extern jclass privkey_class;
extern jclass keypair_class;
extern jclass elliptic_curve_class;
extern jclass fp_field_class;
extern jclass f2m_field_class;
extern jclass point_class;
extern jclass biginteger_class;
extern jclass illegal_state_exception_class;

/**
 * Initialize the classes.
 */
void init_classes(JNIEnv *env, const char* lib_name);

/**
 * Throw a new exception of class with message.
 */
void throw_new(JNIEnv *env, const char *class, const char *message);