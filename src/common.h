#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

    void memwipe(volatile void *ptr, size_t len);

    // Little-endian load/store for 32-bit integers
    uint32_t load32_le(const uint8_t *p);
    void store32_le(uint8_t *p, uint32_t x);

    // Random bytes generation from system entropy source
    bool get_random_bytes(uint8_t *buffer, size_t length);

#ifdef __cplusplus
}
#endif

#endif /* COMMON_H */
