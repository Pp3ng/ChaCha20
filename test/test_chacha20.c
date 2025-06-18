#include "../src/chacha20.h"
#include "test_common.h"

TestStats stats = {0};

static chacha20_ctx *create_context(void)
{
    chacha20_ctx *ctx = chacha20_new();
    if (!ctx)
    {
        printf("❌ Failed to create ChaCha20 context\n");
        exit(EXIT_FAILURE);
    }
    return ctx;
}

TEST(rfc7539_keystream)
{
    const uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

    const uint8_t nonce[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00};

    const uint8_t expected[64] = {
        0x22, 0x4f, 0x51, 0xf3, 0x40, 0x1b, 0xd9, 0xe1,
        0x2f, 0xde, 0x27, 0x6f, 0xb8, 0x63, 0x1d, 0xed,
        0x8c, 0x13, 0x1f, 0x82, 0x3d, 0x2c, 0x06, 0xe2,
        0x7e, 0x4f, 0xca, 0xec, 0x9e, 0xf3, 0xcf, 0x78,
        0x8a, 0x3b, 0x0a, 0xa3, 0x72, 0x60, 0x0a, 0x92,
        0xb5, 0x79, 0x74, 0xcd, 0xed, 0x2b, 0x93, 0x34,
        0x79, 0x4c, 0xba, 0x40, 0xc6, 0x3e, 0x34, 0xcd,
        0xea, 0x21, 0x2c, 0x4c, 0xf0, 0x7d, 0x41, 0xb7};

    chacha20_ctx *ctx = create_context();
    chacha20_init(ctx, key, nonce, 1);

    uint8_t zeros[64] = {0};
    uint8_t keystream[64];
    chacha20_encrypt(ctx, zeros, keystream, 64);

    ASSERT(compare_bytes(keystream, expected, 64), "RFC 7539 keystream generation");

    chacha20_free(ctx);
}

TEST(rfc7539_encryption)
{
    const uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

    const uint8_t nonce[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00};

    const char *plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you "
                            "only one tip for the future, sunscreen would be it.";

    const uint8_t expected_ciphertext[] = {
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
        0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2,
        0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab,
        0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
        0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61,
        0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06,
        0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6,
        0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d};

    size_t text_len = strlen(plaintext);
    uint8_t ciphertext[256];
    uint8_t decrypted[256];

    chacha20_ctx *ctx = create_context();

    // Test encryption
    chacha20_init(ctx, key, nonce, 1);
    chacha20_encrypt(ctx, (const uint8_t *)plaintext, ciphertext, text_len);
    ASSERT(compare_bytes(ciphertext, expected_ciphertext, text_len), "RFC 7539 encryption");

    // Test decryption
    chacha20_init(ctx, key, nonce, 1);
    chacha20_decrypt(ctx, ciphertext, decrypted, text_len);
    decrypted[text_len] = '\0';
    ASSERT(strcmp(plaintext, (char *)decrypted) == 0, "RFC 7539 decryption");

    chacha20_free(ctx);
}

TEST(basic_operations)
{
    const uint8_t key[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                             17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    const uint8_t nonce[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    const char *message = "Hello, ChaCha20!";
    size_t msg_len = strlen(message);

    uint8_t encrypted[64];
    uint8_t decrypted[64];

    chacha20_ctx *ctx = create_context();

    // Basic encrypt/decrypt cycle
    chacha20_init(ctx, key, nonce, 0);
    chacha20_encrypt(ctx, (const uint8_t *)message, encrypted, msg_len);

    chacha20_init(ctx, key, nonce, 0);
    chacha20_decrypt(ctx, encrypted, decrypted, msg_len);
    decrypted[msg_len] = '\0';

    ASSERT(strcmp(message, (char *)decrypted) == 0, "Basic encrypt/decrypt cycle");

    // Test that encryption changes the data
    ASSERT(!compare_bytes((uint8_t *)message, encrypted, msg_len), "Encryption produces different output");

    chacha20_free(ctx);
}

TEST(counter_operations)
{
    const uint8_t key[32] = {0};
    const uint8_t nonce[12] = {0};
    const char *message = "Counter test message";
    size_t msg_len = strlen(message);

    uint8_t encrypted1[64], encrypted2[64], encrypted3[64];

    chacha20_ctx *ctx = create_context();

    // Encrypt with counter 0
    chacha20_init(ctx, key, nonce, 0);
    chacha20_encrypt(ctx, (const uint8_t *)message, encrypted1, msg_len);

    // Encrypt with counter 1
    chacha20_init(ctx, key, nonce, 1);
    chacha20_encrypt(ctx, (const uint8_t *)message, encrypted2, msg_len);

    // Reset counter back to 0 using reinit
    chacha20_reinit(ctx, key, nonce, 0);
    chacha20_encrypt(ctx, (const uint8_t *)message, encrypted3, msg_len);

    ASSERT(!compare_bytes(encrypted1, encrypted2, msg_len), "Different counters produce different output");
    ASSERT(compare_bytes(encrypted1, encrypted3, msg_len), "Counter reset works correctly");

    chacha20_free(ctx);
}

TEST(edge_cases)
{
    const uint8_t key[32] = {0};
    const uint8_t nonce[12] = {0};

    chacha20_ctx *ctx = create_context();
    chacha20_init(ctx, key, nonce, 0);

    // Test zero-length encryption
    uint8_t dummy;
    chacha20_encrypt(ctx, &dummy, &dummy, 0);
    ASSERT(1, "Zero-length encryption doesn't crash");

    // Test context clear
    chacha20_clear(ctx);
    chacha20_encrypt(ctx, &dummy, &dummy, 0);
    ASSERT(1, "Context clear doesn't crash");

    chacha20_free(ctx);

    // Test null context operations
    ASSERT(chacha20_new() != NULL, "Context creation succeeds");
}

TEST(stream_properties)
{
    const uint8_t key[32] = {
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a,
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
        0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09,
        0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0};

    const uint8_t nonce[12] = {0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0};

    // Test multi-block message
    const char *long_message = "This message spans multiple ChaCha20 blocks to test stream cipher properties. "
                               "Stream ciphers should maintain consistency across block boundaries and provide "
                               "the same keystream regardless of how the data is chunked during processing.";

    size_t msg_len = strlen(long_message);
    uint8_t encrypted_full[256];
    uint8_t encrypted_chunks[256];
    uint8_t decrypted[256];

    chacha20_ctx *ctx = create_context();

    // Encrypt all at once
    chacha20_init(ctx, key, nonce, 0);
    chacha20_encrypt(ctx, (const uint8_t *)long_message, encrypted_full, msg_len);

    // Encrypt in chunks
    chacha20_init(ctx, key, nonce, 0);
    size_t chunk1_len = 30;
    size_t chunk2_len = msg_len - chunk1_len;
    chacha20_encrypt(ctx, (const uint8_t *)long_message, encrypted_chunks, chunk1_len);
    chacha20_encrypt(ctx, (const uint8_t *)long_message + chunk1_len, encrypted_chunks + chunk1_len, chunk2_len);

    ASSERT(compare_bytes(encrypted_full, encrypted_chunks, msg_len), "Chunked encryption matches full encryption");

    // Test decryption
    chacha20_init(ctx, key, nonce, 0);
    chacha20_decrypt(ctx, encrypted_full, decrypted, msg_len);
    decrypted[msg_len] = '\0';

    ASSERT(strcmp(long_message, (char *)decrypted) == 0, "Multi-block decryption works correctly");

    chacha20_free(ctx);
}

int main(void)
{
    printf("ChaCha20 Test Suite\n");

    // Run all test suites
    RUN_TEST(rfc7539_keystream);
    RUN_TEST(rfc7539_encryption);
    RUN_TEST(basic_operations);
    RUN_TEST(counter_operations);
    RUN_TEST(edge_cases);
    RUN_TEST(stream_properties);

    // Print final results
    print_summary();

    return get_test_exit_code();
}
