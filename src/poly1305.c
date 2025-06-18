#include "poly1305.h"
#include "common.h"
#include <string.h>
#include <stdlib.h>

// Core Constants
#define POLY1305_BLOCK_SIZE 16
#define POLY1305_ROUNDS 1
#define POLY1305_LIMB_BITS 26

// Poly1305 prime field constants
static const uint32_t POLY1305_LIMB_MASK = 0x3ffffff; // 26-bit limb mask
static const uint32_t POLY1305_REDUCTION = 5;         // Reduction constant

// Limb layout
typedef enum
{
    LIMB_R_START = 0,
    LIMB_S_START = 4,
    LIMB_H_START = 5
} poly1305_limb_layout_t;

// Word Counts (in 32-bit words and limbs)
typedef enum
{
    WORDS_IN_POLY_KEY = 8,
    LIMBS_IN_POLY_R = 5,
    WORDS_IN_POLY_S = 4,
    LIMBS_IN_HASH_STATE = 5,
    WORDS_IN_HASH_PACK = 4
} poly1305_word_counts_t;

// Structure Definition
struct poly1305_ctx
{
    uint32_t r_limbs[LIMBS_IN_POLY_R];        // R key limbs in radix-26
    uint32_t s_words[WORDS_IN_POLY_S];        // S key words for final step
    uint32_t h_state[LIMBS_IN_POLY_R];        // Running hash state
    uint8_t data_buffer[POLY1305_BLOCK_SIZE]; // Buffered input data
    size_t buffer_used;                       // Bytes in buffer
    bool finalized;                           // Processing complete flag
    uint8_t final_tag[POLY1305_TAG_SIZE];     // Cached result tag
};

// Poly1305 Core Algorithm

// Load R coefficients and precompute shifted values
static void load_poly1305_coefficients(const poly1305_ctx *ctx,
                                       uint32_t r[LIMBS_IN_POLY_R], uint32_t s[WORDS_IN_POLY_S])
{
    // Load R coefficients from context and precompute shifted values
    memcpy(r, ctx->r_limbs, sizeof(ctx->r_limbs));
    for (size_t i = 0; i < WORDS_IN_POLY_S; i++)
        s[i] = r[i + 1] * POLY1305_REDUCTION;
}

// Add message block (h += m)
static void add_message_block(uint32_t h[LIMBS_IN_HASH_STATE], const uint8_t *input_data, uint32_t hi_bit)
{
    uint32_t offsets[] = {0, 3, 6, 9, 12};
    uint32_t shifts[] = {0, 2, 4, 6, 8};

    for (size_t i = 0; i < WORDS_IN_POLY_S; i++)
        h[i] += (load32_le(input_data + offsets[i]) >> shifts[i]) & POLY1305_LIMB_MASK;
    h[WORDS_IN_POLY_S] += (load32_le(input_data + 12) >> 8) | hi_bit;
}

// Multiply hash by R coefficients (h *= r)
static void multiply_hash_by_r(const uint32_t h[LIMBS_IN_HASH_STATE], const uint32_t r[LIMBS_IN_POLY_R],
                               const uint32_t s[WORDS_IN_POLY_S], uint64_t t[LIMBS_IN_HASH_STATE])
{
    t[0] = ((uint64_t)h[0] * r[0]) + ((uint64_t)h[1] * s[3]) + ((uint64_t)h[2] * s[2]) +
           ((uint64_t)h[3] * s[1]) + ((uint64_t)h[4] * s[0]);
    t[1] = ((uint64_t)h[0] * r[1]) + ((uint64_t)h[1] * r[0]) + ((uint64_t)h[2] * s[3]) +
           ((uint64_t)h[3] * s[2]) + ((uint64_t)h[4] * s[1]);
    t[2] = ((uint64_t)h[0] * r[2]) + ((uint64_t)h[1] * r[1]) + ((uint64_t)h[2] * r[0]) +
           ((uint64_t)h[3] * s[3]) + ((uint64_t)h[4] * s[2]);
    t[3] = ((uint64_t)h[0] * r[3]) + ((uint64_t)h[1] * r[2]) + ((uint64_t)h[2] * r[1]) +
           ((uint64_t)h[3] * r[0]) + ((uint64_t)h[4] * s[3]);
    t[4] = ((uint64_t)h[0] * r[4]) + ((uint64_t)h[1] * r[3]) + ((uint64_t)h[2] * r[2]) +
           ((uint64_t)h[3] * r[1]) + ((uint64_t)h[4] * r[0]);
}

// Perform carry propagation maintain limb bounds
static void propagate_limb_carries(const uint64_t t[LIMBS_IN_HASH_STATE], uint32_t h[LIMBS_IN_HASH_STATE])
{
    uint64_t temp[LIMBS_IN_HASH_STATE];
    memcpy(temp, t, sizeof(temp));

    for (size_t i = 0; i < WORDS_IN_POLY_S; i++)
    {
        temp[i + 1] += temp[i] >> POLY1305_LIMB_BITS;
        h[i] = temp[i] & POLY1305_LIMB_MASK;
    }
    h[0] += (temp[WORDS_IN_POLY_S] >> POLY1305_LIMB_BITS) * POLY1305_REDUCTION;
    h[WORDS_IN_POLY_S] = temp[WORDS_IN_POLY_S] & POLY1305_LIMB_MASK;
    h[1] += h[0] >> POLY1305_LIMB_BITS;
    h[0] = h[0] & POLY1305_LIMB_MASK;
}

// Process single block through polynomial evaluation
static void process_single_block(uint32_t h[LIMBS_IN_HASH_STATE], const uint32_t r[LIMBS_IN_POLY_R],
                                 const uint32_t s[WORDS_IN_POLY_S], const uint8_t *input_data,
                                 uint32_t hi_bit)
{
    uint64_t t[LIMBS_IN_HASH_STATE];

    // Add message block to hash state
    add_message_block(h, input_data, hi_bit);

    // Multiply hash by R coefficients
    multiply_hash_by_r(h, r, s, t);

    // Propagate carries to maintain limb bounds
    propagate_limb_carries(t, h);
}

// Core mathematical operation: process data blocks through polynomial evaluation
static unsigned int process_poly1305_blocks(poly1305_ctx *ctx, const uint8_t *input_data,
                                            unsigned int input_length, uint32_t hi_bit)
{
    uint32_t r[LIMBS_IN_POLY_R], s[WORDS_IN_POLY_S], h[LIMBS_IN_HASH_STATE];

    // Load coefficients and hash state
    load_poly1305_coefficients(ctx, r, s);
    memcpy(h, ctx->h_state, sizeof(h));

    // Process each complete data block
    while (input_length >= POLY1305_BLOCK_SIZE)
    {
        process_single_block(h, r, s, input_data, hi_bit);

        // Move to next input block
        input_data += POLY1305_BLOCK_SIZE;
        input_length -= POLY1305_BLOCK_SIZE;
    }

    // Store updated hash state
    memcpy(ctx->h_state, h, sizeof(h));

    return input_length;
}

// Data processing pipeline: handle buffering and block processing
static void run_poly1305_update(poly1305_ctx *ctx, const uint8_t *data,
                                size_t data_len)
{
    // Validate input parameters and state
    if (!ctx || ctx->finalized || (data_len > 0 && !data))
        return;

    unsigned int bytes_to_copy;
    const uint8_t *data_ptr = data;
    unsigned int bytes_remaining = data_len;

    // Process any previously buffered data
    if (ctx->buffer_used)
    {
        bytes_to_copy = (bytes_remaining < POLY1305_BLOCK_SIZE - ctx->buffer_used) ? bytes_remaining : POLY1305_BLOCK_SIZE - ctx->buffer_used;
        memcpy(ctx->data_buffer + ctx->buffer_used, data_ptr, bytes_to_copy);
        data_ptr += bytes_to_copy;
        bytes_remaining -= bytes_to_copy;
        ctx->buffer_used += bytes_to_copy;

        // Process completed buffer
        if (ctx->buffer_used == POLY1305_BLOCK_SIZE)
        {
            process_poly1305_blocks(ctx, ctx->data_buffer, POLY1305_BLOCK_SIZE, 1 << 24);
            ctx->buffer_used = 0;
        }
    }

    // Process complete blocks directly from input
    if (bytes_remaining >= POLY1305_BLOCK_SIZE)
    {
        bytes_to_copy = process_poly1305_blocks(ctx, data_ptr, bytes_remaining, 1 << 24);
        data_ptr += bytes_remaining - bytes_to_copy;
        bytes_remaining = bytes_to_copy;
    }

    // Buffer any remaining partial block
    if (bytes_remaining)
    {
        ctx->buffer_used = bytes_remaining;
        memcpy(ctx->data_buffer, data_ptr, bytes_remaining);
    }
}

// Public API

// Create and initialize a new Poly1305 context
poly1305_ctx *poly1305_new(void)
{
    poly1305_ctx *ctx = malloc(sizeof(poly1305_ctx));
    if (ctx)
        memset(ctx, 0, sizeof(poly1305_ctx));
    return ctx;
}

// Securely destroy a Poly1305 context
void poly1305_free(poly1305_ctx *ctx)
{
    if (ctx)
    {
        poly1305_clear(ctx); // Clear sensitive data first
        free(ctx);
    }
}

// Initialize Poly1305 state with 256-bit key
void poly1305_init(poly1305_ctx *ctx, const uint8_t key[POLY1305_KEY_SIZE])
{
    // Parameter validation
    if (!ctx || !key)
        return;

    // Initialize context to clean state
    memset(ctx, 0, sizeof(poly1305_ctx));

    // Extract and clamp R key (first 16 bytes) - Apply clamping: r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
    uint32_t clamp[] = {0x3ffffff, 0x3ffff03, 0x3ffc0ff, 0x3f03fff, 0x00fffff};
    uint32_t offsets[] = {0, 3, 6, 9, 12};
    uint32_t shifts[] = {0, 2, 4, 6, 8};

    for (size_t i = 0; i < LIMBS_IN_POLY_R; i++)
        ctx->r_limbs[i] = (load32_le(key + offsets[i]) >> shifts[i]) & clamp[i];

    // Extract S key (last 16 bytes)
    for (size_t i = 0; i < WORDS_IN_POLY_S; i++)
        ctx->s_words[i] = load32_le(key + 16 + i * 4);
}

// Update authentication state with additional data
void poly1305_update(poly1305_ctx *ctx, const uint8_t *data, size_t data_len)
{
    run_poly1305_update(ctx, data, data_len);
}

// Handle final partial block with padding
static void handle_final_block(poly1305_ctx *ctx)
{
    if (ctx->buffer_used)
    {
        ctx->data_buffer[ctx->buffer_used++] = 1; // Add padding bit
        memset(ctx->data_buffer + ctx->buffer_used, 0,
               POLY1305_BLOCK_SIZE - ctx->buffer_used);
        process_poly1305_blocks(ctx, ctx->data_buffer, POLY1305_BLOCK_SIZE, 0);
    }
}

// Complete carry propagation for hash state
static void propagate_carries(uint32_t h[LIMBS_IN_HASH_STATE])
{
    for (size_t i = 1; i < LIMBS_IN_HASH_STATE; i++)
    {
        h[i] += (h[i - 1] >> POLY1305_LIMB_BITS);
        h[i - 1] &= POLY1305_LIMB_MASK;
    }
    h[0] += (h[WORDS_IN_POLY_S] >> POLY1305_LIMB_BITS) * POLY1305_REDUCTION;
    h[WORDS_IN_POLY_S] &= POLY1305_LIMB_MASK;
    h[1] += (h[0] >> POLY1305_LIMB_BITS);
    h[0] &= POLY1305_LIMB_MASK;
}

// Perform modular reduction and conditional selection
static void modular_reduce(uint32_t h[LIMBS_IN_HASH_STATE])
{
    uint32_t g[LIMBS_IN_HASH_STATE];

    // Test if modular reduction is needed: compute h + (-p)
    g[0] = h[0] + POLY1305_REDUCTION;
    for (size_t i = 1; i < WORDS_IN_POLY_S; i++)
    {
        g[i] = h[i] + (g[i - 1] >> POLY1305_LIMB_BITS);
        g[i - 1] &= POLY1305_LIMB_MASK;
    }
    g[WORDS_IN_POLY_S] = h[WORDS_IN_POLY_S] + (g[WORDS_IN_POLY_S - 1] >> POLY1305_LIMB_BITS) - (1 << POLY1305_LIMB_BITS);
    g[WORDS_IN_POLY_S - 1] &= POLY1305_LIMB_MASK;

    // Conditional selection based on overflow
    uint32_t mask = (g[WORDS_IN_POLY_S] >> ((sizeof(uint32_t) * 8) - 1)) - 1;
    for (size_t i = 0; i < LIMBS_IN_HASH_STATE; i++)
    {
        g[i] &= mask;
        h[i] = (h[i] & ~mask) | g[i];
    }
}

// Pack hash limbs into 128-bit format
static void pack_hash_to_words(const uint32_t h[LIMBS_IN_HASH_STATE], uint32_t words[WORDS_IN_HASH_PACK])
{
    words[0] = (h[0] >> 0) | (h[1] << POLY1305_LIMB_BITS);
    words[1] = (h[1] >> 6) | (h[2] << 20);
    words[2] = (h[2] >> 12) | (h[3] << 14);
    words[3] = (h[3] >> 18) | (h[4] << 8);
}

// Compute final MAC: (h + s) % (2^128)
static void compute_final_mac(const uint32_t h_words[WORDS_IN_HASH_PACK], const uint32_t s_words[WORDS_IN_POLY_S], uint8_t tag[POLY1305_TAG_SIZE])
{
    uint64_t f = 0;
    for (size_t i = 0; i < WORDS_IN_HASH_PACK; i++)
    {
        f = (f >> 32) + h_words[i] + s_words[i];
        store32_le(tag + (i * 4), f);
    }
}

// Generate final authentication tag from accumulated state
void poly1305_finalize(poly1305_ctx *ctx, uint8_t tag[POLY1305_TAG_SIZE])
{
    // Parameter validation
    if (!ctx || !tag)
        return;

    // Return cached tag if already computed
    if (ctx->finalized)
    {
        memcpy(tag, ctx->final_tag, POLY1305_TAG_SIZE);
        return;
    }

    // Process final block with padding if needed
    handle_final_block(ctx);

    // Copy hash state for final processing
    uint32_t h[LIMBS_IN_HASH_STATE];
    memcpy(h, ctx->h_state, sizeof(h));

    // Complete the hash computation
    propagate_carries(h);
    modular_reduce(h);

    // Convert to final format and compute MAC
    uint32_t h_words[WORDS_IN_HASH_PACK];
    pack_hash_to_words(h, h_words);
    compute_final_mac(h_words, ctx->s_words, tag);

    // Cache computed tag and mark as complete
    memcpy(ctx->final_tag, tag, POLY1305_TAG_SIZE);
    ctx->finalized = true;
}

// One-shot authentication: complete MAC computation in single call
void poly1305_auth(const uint8_t key[POLY1305_KEY_SIZE],
                   const uint8_t *message, size_t message_len,
                   uint8_t auth_tag[POLY1305_TAG_SIZE])
{
    poly1305_ctx *ctx = poly1305_new();
    if (!ctx)
        return;

    poly1305_init(ctx, key);
    if (message && message_len > 0)
        poly1305_update(ctx, message, message_len);
    poly1305_finalize(ctx, auth_tag);
    poly1305_free(ctx);
}

// Constant-time tag verification to prevent timing attacks
bool poly1305_verify(const uint8_t expected_tag[POLY1305_TAG_SIZE],
                     const uint8_t computed_tag[POLY1305_TAG_SIZE])
{
    // Parameter validation
    if (!expected_tag || !computed_tag)
        return false;

    // Bitwise difference accumulation for constant-time comparison
    uint8_t diff_accumulator = 0;
    for (size_t i = 0; i < POLY1305_TAG_SIZE; i++)
        diff_accumulator |= expected_tag[i] ^ computed_tag[i];
    return diff_accumulator == 0;
}

// Securely clear all sensitive data from context
void poly1305_clear(poly1305_ctx *ctx)
{
    if (!ctx)
        return;
    memwipe(ctx, sizeof(*ctx));
}
