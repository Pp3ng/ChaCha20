#include "chacha20.h"
#include <string.h>
#include <stdlib.h>

// Core Constants
#define CHACHA20_BLOCK_SIZE 64
#define CHACHA20_ROUNDS 20
#define CHACHA20_DOUBLE_ROUNDS (CHACHA20_ROUNDS / 2)

// ChaCha20 magic constants
static const uint32_t CHACHA20_SIGMA[4] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 // "expand 32-byte k"
};

// State Array Layout
typedef enum
{
    STATE_CONSTANTS_START = 0,
    STATE_KEY_START = 4,
    STATE_COUNTER_INDEX = 12,
    STATE_NONCE_START = 13
} chacha20_state_layout_t;

// Size Constants (in 32-bit words)
typedef enum
{
    WORDS_IN_KEY = 8,
    WORDS_IN_NONCE = 3,
    WORDS_IN_STATE = 16
} chacha20_word_counts_t;

// Structure Definition
struct chacha20_ctx
{
    uint32_t state[WORDS_IN_STATE];         // State matrix
    uint8_t keystream[CHACHA20_BLOCK_SIZE]; // Current keystream block
    size_t keystream_pos;                   // Position in current keystream
};

// Utility Functions

// Secure memory clearing to prevent compiler optimization
static inline void secure_memzero(volatile void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    // Calm memory
    while (len--> 0)
        *p++ = 0;
}

// Little-endian load/store for 32-bit integers
static inline uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t *p, uint32_t x)
{
    p[0] = (uint8_t)(x & 0xFF);
    p[1] = (uint8_t)((x >> 8) & 0xFF);
    p[2] = (uint8_t)((x >> 16) & 0xFF);
    p[3] = (uint8_t)((x >> 24) & 0xFF);
}

// Rotate left for 32-bit integers
static inline uint32_t rotl32(uint32_t x, unsigned int n)
{
    return (x << n) | (x >> (32 - n));
}

// ChaCha20 Core Algorithm

// Core quarter round operation
static inline void quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    *a += *b;  *d ^= *a;  *d = rotl32(*d, 16);
    *c += *d;  *b ^= *c;  *b = rotl32(*b, 12);
    *a += *b;  *d ^= *a;  *d = rotl32(*d, 8);
    *c += *d;  *b ^= *c;  *b = rotl32(*b, 7);
}

// Column rounds: operate on columns of the state matrix
static inline void perform_column_rounds(uint32_t state[WORDS_IN_STATE])
{
    quarter_round(&state[0], &state[4], &state[8], &state[12]);
    quarter_round(&state[1], &state[5], &state[9], &state[13]);
    quarter_round(&state[2], &state[6], &state[10], &state[14]);
    quarter_round(&state[3], &state[7], &state[11], &state[15]);
}

// Diagonal rounds: operate on diagonals of the state matrix
static inline void perform_diagonal_rounds(uint32_t state[WORDS_IN_STATE])
{
    quarter_round(&state[0], &state[5], &state[10], &state[15]);
    quarter_round(&state[1], &state[6], &state[11], &state[12]);
    quarter_round(&state[2], &state[7], &state[8], &state[13]);
    quarter_round(&state[3], &state[4], &state[9], &state[14]);
}

// Generate a 64-byte keystream block from current state
static void generate_keystream_block(chacha20_ctx *ctx)
{
    uint32_t working_state[WORDS_IN_STATE];

    // Copy state to working state
    memcpy(working_state, ctx->state, sizeof(working_state));

    // Perform 20 rounds (10 double rounds) of ChaCha20 transformation
    for (int round = 0; round < CHACHA20_DOUBLE_ROUNDS; round++)
    {
        perform_column_rounds(working_state);
        perform_diagonal_rounds(working_state);
    }

    // Add original state to working state
    for (int i = 0; i < WORDS_IN_STATE; i++)
        working_state[i] += ctx->state[i];

    // Serialize working state to little-endian keystream bytes
    for (int i = 0; i < WORDS_IN_STATE; i++)
        store32_le(ctx->keystream + (i << 2), working_state[i]);

    // Increment counter and reset keystream position
    ctx->state[STATE_COUNTER_INDEX]++;
    ctx->keystream_pos = 0;

    // Securely clear the working state
    secure_memzero(working_state, sizeof(working_state));
}

// Core stream cipher processing: XOR input with keystream
static void process_stream_cipher(chacha20_ctx *ctx, const uint8_t *input,
                                  uint8_t *output, size_t length)
{
    // Early return for invalid parameters
    if (!ctx || !input || !output || length == 0)
        return;

    size_t processed = 0;

    while (processed < length)
    {
        // Generate fresh keystream block if current one is exhausted
        if (ctx->keystream_pos >= CHACHA20_BLOCK_SIZE)
            generate_keystream_block(ctx);

        // Calculate optimal chunk size for this iteration
        const size_t keystream_available = CHACHA20_BLOCK_SIZE - ctx->keystream_pos;
        const size_t data_remaining = length - processed;
        const size_t chunk_size = (keystream_available < data_remaining)
                                      ? keystream_available
                                      : data_remaining;

        // XOR input data with keystream
        const uint8_t *keystream_ptr = ctx->keystream + ctx->keystream_pos;
        for (size_t i = 0; i < chunk_size; i++)
            output[processed + i] = input[processed + i] ^ keystream_ptr[i];

        // Update counters
        processed += chunk_size;
        ctx->keystream_pos += chunk_size;
    }
}

// Public API

// Create and initialize a new ChaCha20 context
chacha20_ctx *chacha20_new(void)
{
    chacha20_ctx *ctx = malloc(sizeof(chacha20_ctx));
    if (ctx)
        memset(ctx, 0, sizeof(chacha20_ctx));
    return ctx;
}

// Securely destroy a ChaCha20 context
void chacha20_free(chacha20_ctx *ctx)
{
    if (ctx)
    {
        chacha20_clear(ctx); // Clear sensitive data first
        free(ctx);
    }
}

// Initialize ChaCha20 state with key, nonce, and counter
void chacha20_init(chacha20_ctx *ctx, const uint8_t key[CHACHA20_KEY_SIZE],
                   const uint8_t nonce[CHACHA20_NONCE_SIZE], uint32_t counter)
{
    // Parameter validation
    if (!ctx || !key || !nonce)
        return;

    // Set up ChaCha20 constants ("expand 32-byte k")
    memcpy(ctx->state, CHACHA20_SIGMA, sizeof(CHACHA20_SIGMA));

    // Load 256-bit key into state (8 words)
    for (int i = 0; i < WORDS_IN_KEY; i++)
        ctx->state[STATE_KEY_START + i] = load32_le(key + (i << 2));

    // Set initial counter value
    ctx->state[STATE_COUNTER_INDEX] = counter;

    // Load 96-bit nonce into state (3 words)
    for (int i = 0; i < WORDS_IN_NONCE; i++)
        ctx->state[STATE_NONCE_START + i] = load32_le(nonce + (i << 2));

    // Force keystream generation on first use
    ctx->keystream_pos = CHACHA20_BLOCK_SIZE;
}

// Encrypt data (ChaCha20 is symmetric: encrypt = decrypt)
void chacha20_encrypt(chacha20_ctx *ctx, const uint8_t *plaintext,
                      uint8_t *ciphertext, size_t length)
{
    process_stream_cipher(ctx, plaintext, ciphertext, length);
}

// Decrypt data (identical to encrypt for stream ciphers)
void chacha20_decrypt(chacha20_ctx *ctx, const uint8_t *ciphertext,
                      uint8_t *plaintext, size_t length)
{
    process_stream_cipher(ctx, ciphertext, plaintext, length);
}

// Reset counter to specific value (use with caution)
void chacha20_reset_counter(chacha20_ctx *ctx, uint32_t counter)
{
    if (!ctx)
        return;

    ctx->state[STATE_COUNTER_INDEX] = counter;
    ctx->keystream_pos = CHACHA20_BLOCK_SIZE; // Force fresh keystream
}

// Securely clear all sensitive data from context
void chacha20_clear(chacha20_ctx *ctx)
{
    if (!ctx)
        return;

    // Zero out all sensitive state data
    secure_memzero(ctx->state, sizeof(ctx->state));
    secure_memzero(ctx->keystream, sizeof(ctx->keystream));
    ctx->keystream_pos = CHACHA20_BLOCK_SIZE;
}
