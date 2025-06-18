#include "common.h"
#include <stdio.h>

// Secure memory clearing
void memwipe(volatile void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    // Clear memory
    while (len-- > 0)
        *p++ = 0;
}

// Little-endian 32-bit load/store
uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

void store32_le(uint8_t *p, uint32_t x)
{
    p[0] = (uint8_t)(x & 0xFF);
    p[1] = (uint8_t)((x >> 8) & 0xFF);
    p[2] = (uint8_t)((x >> 16) & 0xFF);
    p[3] = (uint8_t)((x >> 24) & 0xFF);
}

bool get_random_bytes(uint8_t *buffer, size_t length)
{
    if (!buffer || length == 0)
        return false;

    FILE *urandom = fopen("/dev/urandom", "rb");
    if (!urandom)
        return false;

    bool success = (fread(buffer, 1, length, urandom) == length);
    fclose(urandom);

    return success;
}
