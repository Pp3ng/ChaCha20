#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct
{
    int total, passed, failed;
} TestStats;

// Global test statistics
extern TestStats stats;

// Test definition macro
#define TEST(name)                       \
    static void test_##name(void);       \
    static void run_##name(void)         \
    {                                    \
        printf("\n--- %s ---\n", #name); \
        test_##name();                   \
    }                                    \
    static void test_##name(void)

// Assertion macro
#define ASSERT(condition, message)     \
    do                                 \
    {                                  \
        stats.total++;                 \
        if (condition)                 \
        {                              \
            stats.passed++;            \
            printf("✓ %s\n", message); \
        }                              \
        else                           \
        {                              \
            stats.failed++;            \
            printf("✗ %s\n", message); \
        }                              \
    } while (0)

// Test runner macro
#define RUN_TEST(name) run_##name()

// Compare two byte arrays for equality
static inline bool compare_bytes(const uint8_t *a, const uint8_t *b, size_t len)
{
    return memcmp(a, b, len) == 0;
}

// Print test summary and statistics
static inline void print_summary(void)
{
    printf("\n=== Test Summary ===\n");
    printf("Total: %d | Passed: %d | Failed: %d\n",
           stats.total, stats.passed, stats.failed);
    printf("Success Rate: %.1f%%\n",
           stats.total > 0 ? (100.0 * stats.passed / stats.total) : 0.0);

    if (stats.failed == 0)
        printf("🎉 All tests passed!\n");
    else
        printf("❌ %d test(s) failed\n", stats.failed);
}

// Initialize test statistics
static inline void init_test_stats(void)
{
    stats.total = 0;
    stats.passed = 0;
    stats.failed = 0;
}

// Get test exit code based on results
static inline int get_test_exit_code(void)
{
    return stats.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

#endif // TEST_COMMON_H
