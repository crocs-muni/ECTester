#include "KeccakPRG.h"
#include <stdint.h>

typedef KeccakWidth200_SpongePRG_Instance prng_state;

void prng_init(prng_state *state);

void prng_seed(prng_state *state, const uint8_t *seed, size_t size);

void prng_get(prng_state *state, uint8_t *out, size_t size);



