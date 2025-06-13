#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define CHACHA20_KEY_SIZE 32
#define CHACHA20_NONCE_SIZE 12

    // Opaque context structure - hide implementation details
    typedef struct chacha20_ctx chacha20_ctx;

    // Context management functions
    chacha20_ctx *chacha20_new(void);
    void chacha20_free(chacha20_ctx *ctx);

    void chacha20_init(chacha20_ctx *ctx, const uint8_t key[CHACHA20_KEY_SIZE],
                       const uint8_t nonce[CHACHA20_NONCE_SIZE], uint32_t counter);

    void chacha20_encrypt(chacha20_ctx *ctx, const uint8_t *plaintext, uint8_t *ciphertext, size_t length);

    void chacha20_decrypt(chacha20_ctx *ctx, const uint8_t *ciphertext, uint8_t *plaintext, size_t length);

    void chacha20_reset_counter(chacha20_ctx *ctx, uint32_t counter);

    void chacha20_clear(chacha20_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* CHACHA20_H */
