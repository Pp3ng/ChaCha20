#include "../src/aead.h"
#include "../src/chacha20.h"
#include "test_common.h"

TestStats stats = {0};

static aead_stream_ctx *create_stream_context(void)
{
    aead_stream_ctx *ctx = aead_stream_new();
    if (!ctx)
    {
        printf("❌ Failed to create AEAD stream context\n");
        exit(EXIT_FAILURE);
    }
    return ctx;
}

TEST(rfc7539_aead_vector)
{
    // Test vector data (from RFC 7539)
    uint8_t key[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f};

    uint8_t nonce[12] = {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47};

    const char *plaintext_str = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const char *aad_str = "50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7";

    // Convert hex AAD to bytes
    uint8_t aad[12];
    for (int i = 0; i < 12; i++)
    {
        sscanf(aad_str + i * 3, "%2hhx", &aad[i]);
    }

    size_t plaintext_len = strlen(plaintext_str);
    uint8_t *sealed = malloc(plaintext_len + 16); // ciphertext + tag
    uint8_t *decrypted = malloc(plaintext_len);

    // Seal (one-shot)
    bool success = aead_seal(key, nonce, aad, 12,
                             (uint8_t *)plaintext_str, plaintext_len,
                             sealed);
    ASSERT(success, "RFC 7539 AEAD sealing");

    // Open and verify (one-shot)
    success = aead_open(key, nonce, aad, 12,
                        sealed, plaintext_len + 16, decrypted);
    ASSERT(success, "RFC 7539 AEAD opening");

    // Verify decrypted text matches original
    ASSERT(memcmp(plaintext_str, decrypted, plaintext_len) == 0, "Decrypted plaintext matches original");

    // Test authentication failure with corrupted data
    sealed[0] ^= 0x01; // Corrupt first byte
    success = aead_open(key, nonce, aad, 12,
                        sealed, plaintext_len + 16, decrypted);
    ASSERT(!success, "Authentication correctly rejects corrupted tag");

    free(sealed);
    free(decrypted);
}

TEST(streaming_interface)
{
    uint8_t key[32];
    uint8_t nonce[12];

    // Generate random key and nonce
    ASSERT(chacha20_keygen(key), "Key generation succeeds");
    ASSERT(chacha20_noncegen(nonce), "Nonce generation succeeds");

    const char *message = "This is a test message for streaming AEAD encryption and decryption.";
    size_t msg_len = strlen(message);

    uint8_t *ciphertext = malloc(msg_len);
    uint8_t *decrypted = malloc(msg_len);
    uint8_t tag[16];

    // Test streaming sealing
    aead_stream_ctx *seal_ctx = create_stream_context();
    ASSERT(aead_stream_seal_init(seal_ctx, key, nonce, NULL, 0), "Stream sealing init");

    // Seal in chunks
    size_t chunk_size = 10;
    size_t offset = 0;
    bool seal_success = true;
    while (offset < msg_len && seal_success)
    {
        size_t len = (msg_len - offset < chunk_size) ? msg_len - offset : chunk_size;
        seal_success = aead_stream_seal_update(seal_ctx, (uint8_t *)message + offset, len, ciphertext + offset);
        offset += len;
    }
    ASSERT(seal_success, "Stream sealing update chunks");
    ASSERT(aead_stream_seal_final(seal_ctx, tag), "Stream sealing finalization");
    aead_stream_free(seal_ctx);

    // Test streaming opening
    aead_stream_ctx *open_ctx = create_stream_context();
    ASSERT(aead_stream_open_init(open_ctx, key, nonce, NULL, 0), "Stream opening init");

    // Open in chunks
    offset = 0;
    bool open_success = true;
    while (offset < msg_len && open_success)
    {
        size_t len = (msg_len - offset < chunk_size) ? msg_len - offset : chunk_size;
        open_success = aead_stream_open_update(open_ctx, ciphertext + offset, len, decrypted + offset);
        offset += len;
    }
    ASSERT(open_success, "Stream opening update chunks");
    ASSERT(aead_stream_open_final(open_ctx, tag), "Stream opening finalization");
    aead_stream_free(open_ctx);

    // Verify opened message
    ASSERT(memcmp(message, decrypted, msg_len) == 0, "Streaming opened message matches original");

    free(ciphertext);
    free(decrypted);
}

TEST(empty_message)
{
    uint8_t key[32];
    uint8_t nonce[12];

    ASSERT(chacha20_keygen(key), "Key generation for empty message test");
    ASSERT(chacha20_noncegen(nonce), "Nonce generation for empty message test");

    // Seal empty message
    uint8_t output[16];
    ASSERT(aead_seal(key, nonce, NULL, 0, NULL, 0, output), "Empty message sealing");

    // Open empty message
    uint8_t dummy;
    ASSERT(aead_open(key, nonce, NULL, 0, output, 16, &dummy), "Empty message opening");
}

TEST(basic_operations)
{
    uint8_t key[32];
    uint8_t nonce[12];
    const char *message = "Hello, AEAD!";
    size_t msg_len = strlen(message);
    uint8_t *output = malloc(msg_len + 16); // message + tag
    uint8_t *decrypted = malloc(msg_len);

    ASSERT(chacha20_keygen(key), "Basic key generation");
    ASSERT(chacha20_noncegen(nonce), "Basic nonce generation");

    // Basic sealing
    ASSERT(aead_seal(key, nonce, NULL, 0, (uint8_t *)message, msg_len, output), "Basic sealing");

    // Basic opening
    ASSERT(aead_open(key, nonce, NULL, 0, output, msg_len + 16, decrypted), "Basic opening");

    // Verify message
    ASSERT(memcmp(message, decrypted, msg_len) == 0, "Basic message verification");

    free(output);
    free(decrypted);
}

TEST(context_operations)
{
    // Test stream context creation and destruction
    aead_stream_ctx *stream_ctx = aead_stream_new();
    ASSERT(stream_ctx != NULL, "AEAD stream context creation");
    aead_stream_free(stream_ctx);
}

// Test with AAD
TEST(aad_operations)
{
    uint8_t key[32];
    uint8_t nonce[12];

    ASSERT(chacha20_keygen(key), "Key generation for AAD test");
    ASSERT(chacha20_noncegen(nonce), "Nonce generation for AAD test");

    const char *message = "Hello, with AAD!";
    size_t msg_len = strlen(message);
    const char *aad = "Associated data";
    size_t aad_len = strlen(aad);

    // Test seal with AAD
    uint8_t sealed[256];
    ASSERT(aead_seal(key, nonce, (uint8_t *)aad, aad_len,
                     (uint8_t *)message, msg_len, sealed),
           "Sealing with AAD");

    // Test open with AAD
    uint8_t opened[256];
    ASSERT(aead_open(key, nonce, (uint8_t *)aad, aad_len,
                     sealed, msg_len + AEAD_TAG_SIZE, opened),
           "Opening with AAD");

    // Verify message
    ASSERT(memcmp(message, opened, msg_len) == 0, "AAD message verification");

    // Test with wrong AAD (should fail)
    const char *wrong_aad = "Wrong AAD";
    ASSERT(!aead_open(key, nonce, (uint8_t *)wrong_aad, strlen(wrong_aad),
                      sealed, msg_len + AEAD_TAG_SIZE, opened),
           "Authentication fails with wrong AAD");
}

int main(void)
{
    printf("ChaCha20-Poly1305 AEAD Test Suite\n");

    // Run all test suites
    RUN_TEST(rfc7539_aead_vector);
    RUN_TEST(streaming_interface);
    RUN_TEST(empty_message);
    RUN_TEST(basic_operations);
    RUN_TEST(context_operations);
    RUN_TEST(aad_operations);

    // Print final results
    print_summary();

    return get_test_exit_code();
}
