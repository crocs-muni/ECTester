#include "KeccakPRG.h"
#include "KeccakP-200-compact.c"
#include "KeccakDuplexWidth200.c"
#include "KeccakPRGWidth200.c"
#include "prng.h"
#include <stdlib.h>


void prng_init(prng_state *state) {
	memset(state, 0, sizeof(state));
	KeccakWidth200_SpongePRG_Initialize(state, 70);
}

void prng_seed(prng_state *state, const uint8_t *seed, size_t size) {
	KeccakWidth200_SpongePRG_Feed(state, seed, size);
	KeccakWidth200_SpongePRG_Forget(state);
}

void prng_get(prng_state *state, uint8_t *out, size_t size) {
	KeccakWidth200_SpongePRG_Fetch(state, out, size);
}