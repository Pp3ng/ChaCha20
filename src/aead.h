#ifndef AEAD_H
#define AEAD_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "common.h"

#ifdef __cplusplus
extern "C"
{
#endif

// ChaCha20-Poly1305 AEAD constants
#define AEAD_KEY_SIZE 32   // 256-bit key
#define AEAD_NONCE_SIZE 12 // 96-bit nonce
#define AEAD_TAG_SIZE 16   // 128-bit authentication tag

    // One-shot AEAD operations

    // Seal data
    bool aead_seal(const uint8_t key[AEAD_KEY_SIZE],
                   const uint8_t nonce[AEAD_NONCE_SIZE],
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t *plaintext, size_t plaintext_len,
                   uint8_t *ciphertext_with_tag);

    // Open data
    bool aead_open(const uint8_t key[AEAD_KEY_SIZE],
                   const uint8_t nonce[AEAD_NONCE_SIZE],
                   const uint8_t *aad, size_t aad_len,
                   const uint8_t *ciphertext_with_tag, size_t ciphertext_with_tag_len,
                   uint8_t *plaintext);

    // Streaming AEAD operations for large data
    typedef struct aead_stream_ctx aead_stream_ctx;

    // Streaming context management
    aead_stream_ctx *aead_stream_new(void);
    void aead_stream_free(aead_stream_ctx *ctx);
    void aead_stream_clear(aead_stream_ctx *ctx);

    // Initialize streaming sealing
    bool aead_stream_seal_init(aead_stream_ctx *ctx,
                               const uint8_t key[AEAD_KEY_SIZE],
                               const uint8_t nonce[AEAD_NONCE_SIZE],
                               const uint8_t *aad, size_t aad_len);

    // Update streaming sealing with data chunks
    bool aead_stream_seal_update(aead_stream_ctx *ctx,
                                 const uint8_t *plaintext, size_t plaintext_len,
                                 uint8_t *ciphertext);

    // Finalize streaming sealing and get authentication tag
    bool aead_stream_seal_final(aead_stream_ctx *ctx, uint8_t tag[AEAD_TAG_SIZE]);

    // Initialize streaming opening
    bool aead_stream_open_init(aead_stream_ctx *ctx,
                               const uint8_t key[AEAD_KEY_SIZE],
                               const uint8_t nonce[AEAD_NONCE_SIZE],
                               const uint8_t *aad, size_t aad_len);

    // Update streaming opening with data chunks
    bool aead_stream_open_update(aead_stream_ctx *ctx,
                                 const uint8_t *ciphertext, size_t ciphertext_len,
                                 uint8_t *plaintext);

    // Finalize streaming opening and verify authentication tag
    bool aead_stream_open_final(aead_stream_ctx *ctx, const uint8_t tag[AEAD_TAG_SIZE]);

#ifdef __cplusplus
}
#endif

#endif // AEAD_H
