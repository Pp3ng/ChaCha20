#ifndef POLY1305_H
#define POLY1305_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define POLY1305_KEY_SIZE 32
#define POLY1305_TAG_SIZE 16

    typedef struct poly1305_ctx poly1305_ctx;

    poly1305_ctx *poly1305_new(void);
    void poly1305_free(poly1305_ctx *ctx);

    // Initialize with 256-bit key
    void poly1305_init(poly1305_ctx *ctx, const uint8_t key[POLY1305_KEY_SIZE]);

    // Update with additional authenticated data
    void poly1305_update(poly1305_ctx *ctx, const uint8_t *data, size_t data_len);

    // Finalize and generate 128-bit authentication tag
    void poly1305_finalize(poly1305_ctx *ctx, uint8_t tag[POLY1305_TAG_SIZE]);

    // One-shot authentication function
    void poly1305_auth(const uint8_t key[POLY1305_KEY_SIZE],
                       const uint8_t *message, size_t message_len,
                       uint8_t tag[POLY1305_TAG_SIZE]);

    // Verify authentication tag
    bool poly1305_verify(const uint8_t expected_tag[POLY1305_TAG_SIZE],
                         const uint8_t computed_tag[POLY1305_TAG_SIZE]);

    // Clear sensitive data from context
    void poly1305_clear(poly1305_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* POLY1305_H */
