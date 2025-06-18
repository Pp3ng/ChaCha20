#include "aead.h"
#include "chacha20.h"
#include "poly1305.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Constants
#define AEAD_MAX_DATA_SIZE (1ULL << 38) // ChaCha20 limit (~274 GB)
#define AEAD_MAX_AAD_SIZE (1ULL << 61)  // Poly1305 limit (~2.3 EB)

// Poly1305 processing constants
#define POLY1305_BLOCK_BOUNDARY 16        // 16-byte block alignment
#define POLY1305_LENGTH_FIELD_SIZE 16     // AAD + data length encoding size
#define POLY1305_LENGTH_BYTES_PER_FIELD 8 // 8 bytes per length field
#define AEAD_COUNTER_START_VALUE 1        // ChaCha20 counter starts at 1 for data

// Bit manipulation constants
typedef enum
{
    BITS_PER_BYTE = 8,
    BYTE_MASK = 0xFF
} aead_bit_constants_t;

typedef enum
{
    AEAD_STREAM_STATE_INIT,
    AEAD_STREAM_STATE_SEALING,
    AEAD_STREAM_STATE_OPENING,
    AEAD_STREAM_STATE_FINISHED
} aead_stream_state_t;

// AEAD context structure
typedef struct aead_ctx
{
    chacha20_ctx *chacha_ctx;
    poly1305_ctx *poly_ctx;
    uint8_t poly_key[POLY1305_KEY_SIZE];
} aead_ctx;

static aead_ctx *aead_new(void);
static void aead_free(aead_ctx *ctx);

// Streaming AEAD context structure
struct aead_stream_ctx
{
    chacha20_ctx *chacha_ctx;
    poly1305_ctx *poly_ctx;
    uint8_t poly_key[POLY1305_KEY_SIZE];
    aead_stream_state_t state;
    size_t aad_len;
    size_t data_len;
};

// Validate input lengths against limits
static bool validate_lengths(size_t data_len, size_t aad_len)
{
    return (data_len <= AEAD_MAX_DATA_SIZE) && (aad_len <= AEAD_MAX_AAD_SIZE);
}

// Poly1305 key derivation
static bool derive_poly1305_key(const uint8_t chacha_key[AEAD_KEY_SIZE],
                                const uint8_t nonce[AEAD_NONCE_SIZE],
                                uint8_t poly_key[POLY1305_KEY_SIZE])
{
    chacha20_ctx *ctx = chacha20_new();
    if (!ctx)
        return false;

    // Initialize ChaCha20 with counter 0 to generate Poly1305 key
    chacha20_init(ctx, chacha_key, nonce, 0);

    // Encrypt zeros to derive key
    uint8_t zeros[POLY1305_KEY_SIZE] = {0};
    chacha20_encrypt(ctx, zeros, poly_key, POLY1305_KEY_SIZE);

    chacha20_free(ctx);
    return true;
}

// Process AAD with proper padding
static void process_aad(poly1305_ctx *ctx, const uint8_t *aad, size_t aad_len)
{
    if (aad_len > 0)
    {
        poly1305_update(ctx, aad, aad_len);

        // Pad to 16-byte boundary
        size_t aad_pad = (POLY1305_BLOCK_BOUNDARY - (aad_len % POLY1305_BLOCK_BOUNDARY)) % POLY1305_BLOCK_BOUNDARY;
        if (aad_pad > 0)
        {
            uint8_t zeros[POLY1305_BLOCK_BOUNDARY] = {0};
            poly1305_update(ctx, zeros, aad_pad);
        }
    }
}

// Append length encoding to Poly1305 context
static void append_lengths(poly1305_ctx *ctx, size_t aad_len, size_t data_len)
{
    uint8_t lengths[POLY1305_LENGTH_FIELD_SIZE];
    // AAD length
    for (int i = 0; i < POLY1305_LENGTH_BYTES_PER_FIELD; i++)
        lengths[i] = (aad_len >> (i * BITS_PER_BYTE)) & BYTE_MASK;
    // Data length
    for (int i = 0; i < POLY1305_LENGTH_BYTES_PER_FIELD; i++)
        lengths[POLY1305_LENGTH_BYTES_PER_FIELD + i] = (data_len >> (i * BITS_PER_BYTE)) & BYTE_MASK;
    poly1305_update(ctx, lengths, POLY1305_LENGTH_FIELD_SIZE);
}

// Poly1305 input construction
static bool construct_poly1305_input(poly1305_ctx *ctx,
                                     const uint8_t *aad, size_t aad_len,
                                     const uint8_t *ciphertext, size_t ciphertext_len)
{
    // Process AAD
    process_aad(ctx, aad, aad_len);

    // Process ciphertext
    if (ciphertext_len > 0)
    {
        poly1305_update(ctx, ciphertext, ciphertext_len);

        // Pad to 16-byte boundary
        size_t ct_pad = (POLY1305_BLOCK_BOUNDARY - (ciphertext_len % POLY1305_BLOCK_BOUNDARY)) % POLY1305_BLOCK_BOUNDARY;
        if (ct_pad > 0)
        {
            uint8_t zeros[POLY1305_BLOCK_BOUNDARY] = {0};
            poly1305_update(ctx, zeros, ct_pad);
        }
    }

    // Append lengths
    append_lengths(ctx, aad_len, ciphertext_len);

    return true;
}

static aead_ctx *aead_new(void)
{
    aead_ctx *ctx = calloc(1, sizeof(aead_ctx));
    if (!ctx)
        return NULL;

    ctx->chacha_ctx = chacha20_new();
    ctx->poly_ctx = poly1305_new();

    if (!ctx->chacha_ctx || !ctx->poly_ctx)
    {
        aead_free(ctx);
        return NULL;
    }

    return ctx;
}

static void aead_free(aead_ctx *ctx)
{
    if (!ctx)
        return;

    if (ctx->chacha_ctx)
        chacha20_free(ctx->chacha_ctx);
    if (ctx->poly_ctx)
        poly1305_free(ctx->poly_ctx);
    memwipe(ctx->poly_key, sizeof(ctx->poly_key));
    free(ctx);
}

//  One-shot AEAD encryption with authentication
bool aead_seal(const uint8_t key[AEAD_KEY_SIZE],
               const uint8_t nonce[AEAD_NONCE_SIZE],
               const uint8_t *aad, size_t aad_len,
               const uint8_t *plaintext, size_t plaintext_len,
               uint8_t *ciphertext_with_tag)
{
    if (!key || !nonce || !ciphertext_with_tag)
        return false;
    if (plaintext_len > 0 && !plaintext)
        return false;
    if (aad_len > 0 && !aad)
        return false;

    // Validate input lengths
    if (!validate_lengths(plaintext_len, aad_len))
        return false;

    aead_ctx *ctx = aead_new();
    if (!ctx)
        return false;

    // Step 1: Derive Poly1305 key from ChaCha20's first block
    if (!derive_poly1305_key(key, nonce, ctx->poly_key))
    {
        aead_free(ctx);
        return false;
    }

    // Step 2: Encrypt with ChaCha20 (counter starts at 1)
    chacha20_init(ctx->chacha_ctx, key, nonce, AEAD_COUNTER_START_VALUE);
    if (plaintext_len > 0)
        chacha20_encrypt(ctx->chacha_ctx, plaintext, ciphertext_with_tag, plaintext_len);

    // Step 3: Authenticate with Poly1305
    poly1305_init(ctx->poly_ctx, ctx->poly_key);
    construct_poly1305_input(ctx->poly_ctx, aad, aad_len, ciphertext_with_tag, plaintext_len);
    poly1305_finalize(ctx->poly_ctx, ciphertext_with_tag + plaintext_len);

    // Clear sensitive data and cleanup
    memwipe(ctx->poly_key, sizeof(ctx->poly_key));
    aead_free(ctx);
    return true;
}

// One-shot AEAD decryption with verification
bool aead_open(const uint8_t key[AEAD_KEY_SIZE],
               const uint8_t nonce[AEAD_NONCE_SIZE],
               const uint8_t *aad, size_t aad_len,
               const uint8_t *ciphertext_with_tag, size_t ciphertext_with_tag_len,
               uint8_t *plaintext)
{
    if (!key || !nonce || !ciphertext_with_tag)
        return false;
    if (ciphertext_with_tag_len < AEAD_TAG_SIZE)
        return false;
    if (ciphertext_with_tag_len > AEAD_TAG_SIZE && !plaintext)
        return false;
    if (aad_len > 0 && !aad)
        return false;

    size_t ciphertext_len = ciphertext_with_tag_len - AEAD_TAG_SIZE;
    const uint8_t *ciphertext = ciphertext_with_tag;
    const uint8_t *tag = ciphertext_with_tag + ciphertext_len;

    // Validate input lengths
    if (!validate_lengths(ciphertext_len, aad_len))
        return false;

    aead_ctx *ctx = aead_new();
    if (!ctx)
        return false;

    // Step 1: Derive Poly1305 key from ChaCha20
    if (!derive_poly1305_key(key, nonce, ctx->poly_key))
    {
        aead_free(ctx);
        return false;
    }

    // Step 2: Verify authentication tag
    poly1305_init(ctx->poly_ctx, ctx->poly_key);
    construct_poly1305_input(ctx->poly_ctx, aad, aad_len, ciphertext, ciphertext_len);

    uint8_t computed_tag[AEAD_TAG_SIZE];
    poly1305_finalize(ctx->poly_ctx, computed_tag);

    if (!poly1305_verify(tag, computed_tag))
    {
        // Clear sensitive data on authentication failure
        memwipe(ctx->poly_key, sizeof(ctx->poly_key));
        memwipe(computed_tag, sizeof(computed_tag));
        aead_free(ctx);
        return false;
    }

    // Step 3: Decrypt ciphertext with ChaCha20 (counter starts at 1)
    chacha20_init(ctx->chacha_ctx, key, nonce, AEAD_COUNTER_START_VALUE);
    if (ciphertext_len > 0)
        chacha20_decrypt(ctx->chacha_ctx, ciphertext, plaintext, ciphertext_len);

    // Clear sensitive data and cleanup
    memwipe(ctx->poly_key, sizeof(ctx->poly_key));
    memwipe(computed_tag, sizeof(computed_tag));
    aead_free(ctx);
    return true;
}

// Streaming context management
aead_stream_ctx *aead_stream_new(void)
{
    aead_stream_ctx *ctx = calloc(1, sizeof(aead_stream_ctx));
    if (!ctx)
        return NULL;

    ctx->chacha_ctx = chacha20_new();
    ctx->poly_ctx = poly1305_new();

    if (!ctx->chacha_ctx || !ctx->poly_ctx)
    {
        aead_stream_free(ctx);
        return NULL;
    }

    ctx->state = AEAD_STREAM_STATE_INIT;
    return ctx;
}

void aead_stream_free(aead_stream_ctx *ctx)
{
    if (!ctx)
        return;

    if (ctx->chacha_ctx)
        chacha20_free(ctx->chacha_ctx);
    if (ctx->poly_ctx)
        poly1305_free(ctx->poly_ctx);
    memwipe(ctx->poly_key, sizeof(ctx->poly_key));
    free(ctx);
}

void aead_stream_clear(aead_stream_ctx *ctx)
{
    if (!ctx)
        return;

    if (ctx->chacha_ctx)
        chacha20_clear(ctx->chacha_ctx);
    if (ctx->poly_ctx)
        poly1305_clear(ctx->poly_ctx);
    memwipe(ctx->poly_key, sizeof(ctx->poly_key));
    ctx->state = AEAD_STREAM_STATE_INIT;
    ctx->aad_len = 0;
    ctx->data_len = 0;
}

// Initialize streaming sealing
bool aead_stream_seal_init(aead_stream_ctx *ctx,
                           const uint8_t key[AEAD_KEY_SIZE],
                           const uint8_t nonce[AEAD_NONCE_SIZE],
                           const uint8_t *aad, size_t aad_len)
{
    if (!ctx || !key || !nonce)
        return false;
    if (aad_len > 0 && !aad)
        return false;
    if (ctx->state != AEAD_STREAM_STATE_INIT)
        return false;

    // Validate AAD length
    if (aad_len > AEAD_MAX_AAD_SIZE)
        return false;

    // Derive Poly1305 key
    if (!derive_poly1305_key(key, nonce, ctx->poly_key))
        return false;

    // Initialize ChaCha20 for encryption (counter starts at 1)
    chacha20_init(ctx->chacha_ctx, key, nonce, AEAD_COUNTER_START_VALUE);

    // Initialize Poly1305 and process AAD
    poly1305_init(ctx->poly_ctx, ctx->poly_key);
    process_aad(ctx->poly_ctx, aad, aad_len);

    ctx->aad_len = aad_len;
    ctx->data_len = 0;
    ctx->state = AEAD_STREAM_STATE_SEALING;

    return true;
}

// Update streaming sealing with data chunks
bool aead_stream_seal_update(aead_stream_ctx *ctx,
                             const uint8_t *plaintext, size_t plaintext_len,
                             uint8_t *ciphertext)
{
    if (!ctx || ctx->state != AEAD_STREAM_STATE_SEALING)
        return false;
    if (plaintext_len > 0 && (!plaintext || !ciphertext))
        return false;

    // Check if adding this chunk would exceed the maximum data size
    if (ctx->data_len + plaintext_len > AEAD_MAX_DATA_SIZE)
        return false;

    if (plaintext_len > 0)
    {
        // Encrypt with ChaCha20
        chacha20_encrypt(ctx->chacha_ctx, plaintext, ciphertext, plaintext_len);

        // Authenticate ciphertext with Poly1305
        poly1305_update(ctx->poly_ctx, ciphertext, plaintext_len);

        ctx->data_len += plaintext_len;
    }

    return true;
}

// Finalize streaming sealing and get authentication tag
bool aead_stream_seal_final(aead_stream_ctx *ctx, uint8_t tag[AEAD_TAG_SIZE])
{
    if (!ctx || ctx->state != AEAD_STREAM_STATE_SEALING || !tag)
        return false;

    // Pad ciphertext to 16-byte boundary
    size_t ct_pad = (POLY1305_BLOCK_BOUNDARY - (ctx->data_len % POLY1305_BLOCK_BOUNDARY)) % POLY1305_BLOCK_BOUNDARY;
    if (ct_pad > 0)
    {
        uint8_t zeros[POLY1305_BLOCK_BOUNDARY] = {0};
        poly1305_update(ctx->poly_ctx, zeros, ct_pad);
    }

    // Append lengths and finalize tag
    append_lengths(ctx->poly_ctx, ctx->aad_len, ctx->data_len);
    poly1305_finalize(ctx->poly_ctx, tag);

    // Update state
    ctx->state = AEAD_STREAM_STATE_FINISHED;

    return true;
}

// Initialize streaming opening
bool aead_stream_open_init(aead_stream_ctx *ctx,
                           const uint8_t key[AEAD_KEY_SIZE],
                           const uint8_t nonce[AEAD_NONCE_SIZE],
                           const uint8_t *aad, size_t aad_len)
{
    if (!ctx || !key || !nonce)
        return false;
    if (aad_len > 0 && !aad)
        return false;
    if (ctx->state != AEAD_STREAM_STATE_INIT)
        return false;

    // Validate AAD length
    if (aad_len > AEAD_MAX_AAD_SIZE)
        return false;

    // Derive Poly1305 key
    if (!derive_poly1305_key(key, nonce, ctx->poly_key))
        return false;

    // Initialize ChaCha20 for decryption
    chacha20_init(ctx->chacha_ctx, key, nonce, AEAD_COUNTER_START_VALUE);

    // Initialize Poly1305 and process AAD
    poly1305_init(ctx->poly_ctx, ctx->poly_key);
    process_aad(ctx->poly_ctx, aad, aad_len);

    ctx->aad_len = aad_len;
    ctx->data_len = 0;
    ctx->state = AEAD_STREAM_STATE_OPENING;

    return true;
}

// Update streaming opening with data chunks
bool aead_stream_open_update(aead_stream_ctx *ctx,
                             const uint8_t *ciphertext, size_t ciphertext_len,
                             uint8_t *plaintext)
{
    if (!ctx || ctx->state != AEAD_STREAM_STATE_OPENING)
        return false;
    if (ciphertext_len > 0 && (!ciphertext || !plaintext))
        return false;

    // Check if adding this chunk would exceed the maximum data size
    if (ctx->data_len + ciphertext_len > AEAD_MAX_DATA_SIZE)
        return false;

    if (ciphertext_len > 0)
    {
        // Authenticate ciphertext with Poly1305 first
        poly1305_update(ctx->poly_ctx, ciphertext, ciphertext_len);

        // Decrypt with ChaCha20
        chacha20_decrypt(ctx->chacha_ctx, ciphertext, plaintext, ciphertext_len);

        ctx->data_len += ciphertext_len;
    }

    return true;
}

// Finalize streaming opening and verify authentication tag
bool aead_stream_open_final(aead_stream_ctx *ctx, const uint8_t tag[AEAD_TAG_SIZE])
{
    if (!ctx || ctx->state != AEAD_STREAM_STATE_OPENING || !tag)
        return false;

    // Pad ciphertext to 16-byte boundary
    size_t ct_pad = (POLY1305_BLOCK_BOUNDARY - (ctx->data_len % POLY1305_BLOCK_BOUNDARY)) % POLY1305_BLOCK_BOUNDARY;
    if (ct_pad > 0)
    {
        uint8_t zeros[POLY1305_BLOCK_BOUNDARY] = {0};
        poly1305_update(ctx->poly_ctx, zeros, ct_pad);
    }

    // Append lengths and compute tag
    append_lengths(ctx->poly_ctx, ctx->aad_len, ctx->data_len);

    uint8_t computed_tag[AEAD_TAG_SIZE];
    poly1305_finalize(ctx->poly_ctx, computed_tag);

    bool result = poly1305_verify(tag, computed_tag);

    // Update state and clear computed tag
    ctx->state = AEAD_STREAM_STATE_FINISHED;
    memwipe(computed_tag, sizeof(computed_tag));

    return result;
}
