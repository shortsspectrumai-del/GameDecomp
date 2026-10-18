/* Trusted, project-authored fixture for the opt-in differential demo. */
#include <stdint.h>

uint32_t game_add32(uint32_t a, uint32_t b) {
    return a + b;
}

uint32_t game_mix32(uint32_t a, uint32_t b) {
    return ((a ^ b) << 3) + ((a & b) >> 5);
}

uint64_t game_mul64(uint64_t a, uint64_t b) {
    return a * b;
}

uint64_t game_scale64(uint64_t value) {
    return value * UINT64_C(5) + UINT64_C(13);
}

/* Volatile local memory deliberately lies outside scalar leaf recovery. */
uint32_t game_branch(uint32_t value) {
    volatile uint32_t observed = value;
    if (observed & 1u) {
        return observed * 3u + 1u;
    }
    return observed >> 1;
}
