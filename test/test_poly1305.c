#include "../src/poly1305.h"
#include "test_common.h"

TestStats stats = {0};

static poly1305_ctx *create_context(void)
{
    poly1305_ctx *ctx = poly1305_new();
    if (!ctx)
    {
        printf("✗ Failed to create Poly1305 context\n");
        exit(EXIT_FAILURE);
    }
    return ctx;
}

TEST(rfc7539_test_vector)
{
    // RFC 7539 test vector
    const uint8_t key[32] = {
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b};

    const char *message = "Cryptographic Forum Research Group";
    const uint8_t expected_tag[16] = {
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9};

    uint8_t tag[POLY1305_TAG_SIZE];

    // Test one-shot authentication
    poly1305_auth(key, (const uint8_t *)message, strlen(message), tag);
    ASSERT(compare_bytes(tag, expected_tag, POLY1305_TAG_SIZE), "RFC 7539 test vector (one-shot)");

    // Test streaming authentication
    poly1305_ctx *ctx = create_context();
    poly1305_init(ctx, key);
    poly1305_update(ctx, (const uint8_t *)message, strlen(message));
    poly1305_finalize(ctx, tag);
    ASSERT(compare_bytes(tag, expected_tag, POLY1305_TAG_SIZE), "RFC 7539 test vector (streaming)");

    // Test verification
    ASSERT(poly1305_verify(tag, expected_tag), "Tag verification succeeds");

    // Test verification failure
    uint8_t wrong_tag[POLY1305_TAG_SIZE];
    memcpy(wrong_tag, expected_tag, POLY1305_TAG_SIZE);
    wrong_tag[0] ^= 1; // Flip one bit
    ASSERT(!poly1305_verify(tag, wrong_tag), "Tag verification fails with wrong tag");

    poly1305_free(ctx);
}

TEST(basic_operations)
{
    const uint8_t key[32] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

    const char *message1 = "Hello, Poly1305!";
    const char *message2 = "Different message";

    uint8_t tag1[POLY1305_TAG_SIZE];
    uint8_t tag2[POLY1305_TAG_SIZE];
    uint8_t tag3[POLY1305_TAG_SIZE];

    poly1305_ctx *ctx = create_context();

    // Same message should produce same tag
    poly1305_init(ctx, key);
    poly1305_update(ctx, (const uint8_t *)message1, strlen(message1));
    poly1305_finalize(ctx, tag1);

    poly1305_init(ctx, key);
    poly1305_update(ctx, (const uint8_t *)message1, strlen(message1));
    poly1305_finalize(ctx, tag2);

    ASSERT(compare_bytes(tag1, tag2, POLY1305_TAG_SIZE), "Same message produces same tag");

    // Different message should produce different tag
    poly1305_init(ctx, key);
    poly1305_update(ctx, (const uint8_t *)message2, strlen(message2));
    poly1305_finalize(ctx, tag3);

    ASSERT(!compare_bytes(tag1, tag3, POLY1305_TAG_SIZE), "Different message produces different tag");

    poly1305_free(ctx);
}

TEST(empty_message)
{
    const uint8_t key[32] = {0};
    uint8_t tag1[POLY1305_TAG_SIZE];
    uint8_t tag2[POLY1305_TAG_SIZE];

    // Test empty message with one-shot
    poly1305_auth(key, NULL, 0, tag1);

    // Test empty message with streaming
    poly1305_ctx *ctx = create_context();
    poly1305_init(ctx, key);
    poly1305_finalize(ctx, tag2);

    ASSERT(compare_bytes(tag1, tag2, POLY1305_TAG_SIZE), "Empty message authentication works");

    poly1305_free(ctx);
}

TEST(chunked_input)
{
    const uint8_t key[32] = {
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a,
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
        0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09,
        0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0};

    const char *long_message = "This is a longer message that will be processed in chunks to test "
                               "the streaming functionality of Poly1305. The message should produce "
                               "the same authentication tag regardless of how it's chunked during "
                               "processing, which is a critical property for streaming authentication.";

    size_t msg_len = strlen(long_message);
    uint8_t tag_full[POLY1305_TAG_SIZE];
    uint8_t tag_chunked[POLY1305_TAG_SIZE];

    // Process all at once
    poly1305_auth(key, (const uint8_t *)long_message, msg_len, tag_full);

    // Process in chunks
    poly1305_ctx *ctx = create_context();
    poly1305_init(ctx, key);

    size_t chunk_size = 17; // Odd chunk size to test alignment
    size_t processed = 0;

    while (processed < msg_len)
    {
        size_t remaining = msg_len - processed;
        size_t current_chunk = (remaining < chunk_size) ? remaining : chunk_size;
        poly1305_update(ctx, (const uint8_t *)long_message + processed, current_chunk);
        processed += current_chunk;
    }

    poly1305_finalize(ctx, tag_chunked);

    ASSERT(compare_bytes(tag_full, tag_chunked, POLY1305_TAG_SIZE), "Chunked processing matches full processing");

    poly1305_free(ctx);
}

TEST(different_keys)
{
    const uint8_t key1[32] = {0};
    uint8_t key2[32] = {0};
    key2[0] = 1; // Slightly different key

    const char *message = "Same message, different keys";
    uint8_t tag1[POLY1305_TAG_SIZE];
    uint8_t tag2[POLY1305_TAG_SIZE];

    poly1305_auth(key1, (const uint8_t *)message, strlen(message), tag1);
    poly1305_auth(key2, (const uint8_t *)message, strlen(message), tag2);

    ASSERT(!compare_bytes(tag1, tag2, POLY1305_TAG_SIZE), "Different keys produce different tags");
}

TEST(boundary_conditions)
{
    const uint8_t key[32] = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x06, 0x17,
        0x28, 0x39, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f};

    // Test messages of various lengths around block boundaries
    uint8_t test_data[80];
    for (size_t i = 0; i < sizeof(test_data); i++)
        test_data[i] = (uint8_t)(i & 0xFF);

    uint8_t tag1[POLY1305_TAG_SIZE], tag2[POLY1305_TAG_SIZE];

    // Test 16-byte boundary (exactly one block)
    poly1305_auth(key, test_data, 16, tag1);

    poly1305_ctx *ctx = create_context();
    poly1305_init(ctx, key);
    poly1305_update(ctx, test_data, 16);
    poly1305_finalize(ctx, tag2);

    ASSERT(compare_bytes(tag1, tag2, POLY1305_TAG_SIZE), "16-byte message (one block) works correctly");

    // Test 15-byte message (partial block)
    poly1305_auth(key, test_data, 15, tag1);

    poly1305_init(ctx, key);
    poly1305_update(ctx, test_data, 15);
    poly1305_finalize(ctx, tag2);

    ASSERT(compare_bytes(tag1, tag2, POLY1305_TAG_SIZE), "15-byte message (partial block) works correctly");

    // Test 33-byte message (two blocks + 1 byte)
    poly1305_auth(key, test_data, 33, tag1);

    poly1305_init(ctx, key);
    poly1305_update(ctx, test_data, 33);
    poly1305_finalize(ctx, tag2);

    ASSERT(compare_bytes(tag1, tag2, POLY1305_TAG_SIZE), "33-byte message (2+ blocks) works correctly");

    poly1305_free(ctx);
}

TEST(context_reuse)
{
    const uint8_t key[32] = {
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

    const char *message1 = "First message";
    const char *message2 = "Second message";

    uint8_t tag1[POLY1305_TAG_SIZE], tag2[POLY1305_TAG_SIZE];
    uint8_t tag1_ref[POLY1305_TAG_SIZE], tag2_ref[POLY1305_TAG_SIZE];

    // Get reference tags
    poly1305_auth(key, (const uint8_t *)message1, strlen(message1), tag1_ref);
    poly1305_auth(key, (const uint8_t *)message2, strlen(message2), tag2_ref);

    // Test context reuse
    poly1305_ctx *ctx = create_context();

    // First use
    poly1305_init(ctx, key);
    poly1305_update(ctx, (const uint8_t *)message1, strlen(message1));
    poly1305_finalize(ctx, tag1);

    // Reuse context
    poly1305_init(ctx, key);
    poly1305_update(ctx, (const uint8_t *)message2, strlen(message2));
    poly1305_finalize(ctx, tag2);

    ASSERT(compare_bytes(tag1, tag1_ref, POLY1305_TAG_SIZE), "Context reuse - first message");
    ASSERT(compare_bytes(tag2, tag2_ref, POLY1305_TAG_SIZE), "Context reuse - second message");

    poly1305_free(ctx);
}

TEST(edge_cases)
{
    const uint8_t key[32] = {0};

    poly1305_ctx *ctx = create_context();

    // Test multiple finalizations
    poly1305_init(ctx, key);
    uint8_t tag1[POLY1305_TAG_SIZE], tag2[POLY1305_TAG_SIZE];
    poly1305_finalize(ctx, tag1);
    poly1305_finalize(ctx, tag2); // Second finalize should be no-op

    ASSERT(compare_bytes(tag1, tag2, POLY1305_TAG_SIZE), "Multiple finalization is safe");

    // Test update after finalization (should be ignored)
    poly1305_update(ctx, (const uint8_t *)"ignored", 7);
    uint8_t tag3[POLY1305_TAG_SIZE];
    poly1305_finalize(ctx, tag3);

    ASSERT(compare_bytes(tag1, tag3, POLY1305_TAG_SIZE), "Update after finalization is ignored");

    // Test context clear
    poly1305_clear(ctx);
    ASSERT(1, "Context clear doesn't crash");

    poly1305_free(ctx);
    ASSERT(poly1305_new() != NULL, "Context creation succeeds");
}

int main(void)
{
    printf("Poly1305 Test Suite\n");

    // Run all test suites
    RUN_TEST(rfc7539_test_vector);
    RUN_TEST(basic_operations);
    RUN_TEST(empty_message);
    RUN_TEST(chunked_input);
    RUN_TEST(different_keys);
    RUN_TEST(boundary_conditions);
    RUN_TEST(context_reuse);
    RUN_TEST(edge_cases);

    // Print final results
    print_summary();

    return get_test_exit_code();
}
