#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define CHACHA20_KEY_SIZE 32
#define CHACHA20_NONCE_SIZE 12

    typedef struct chacha20_ctx chacha20_ctx;

    chacha20_ctx *chacha20_new(void);
    void chacha20_free(chacha20_ctx *ctx);

    // Initialize with 256-bit key, 96-bit nonce, and counter
    void chacha20_init(chacha20_ctx *ctx, const uint8_t key[CHACHA20_KEY_SIZE],
                       const uint8_t nonce[CHACHA20_NONCE_SIZE], uint32_t counter);

    // Encrypt plaintext data
    void chacha20_encrypt(chacha20_ctx *ctx, const uint8_t *plaintext, uint8_t *ciphertext, size_t data_len);

    // Decrypt ciphertext data
    void chacha20_decrypt(chacha20_ctx *ctx, const uint8_t *ciphertext, uint8_t *plaintext, size_t data_len);

    // Reinitialize context with new parameters
    void chacha20_reinit(chacha20_ctx *ctx, const uint8_t key[CHACHA20_KEY_SIZE],
                         const uint8_t nonce[CHACHA20_NONCE_SIZE], uint32_t counter);

    // Clear sensitive data from context
    void chacha20_clear(chacha20_ctx *ctx);

    // Generate cryptographically secure random key
    bool chacha20_keygen(uint8_t key[CHACHA20_KEY_SIZE]);

    // Generate cryptographically secure random nonce
    bool chacha20_noncegen(uint8_t nonce[CHACHA20_NONCE_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* CHACHA20_H */
