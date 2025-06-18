#include "src/aead.h"
#include "src/chacha20.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define BUFFER_SIZE 8192 // 8 KB buffer size
#define PROGRESS_INTERVAL (BUFFER_SIZE * 10)
#define PROGRESS_DISPLAY_THRESHOLD 1024                              // Show progress every 1KB
#define HEX_CHARS_PER_BYTE 2                                         // Two hex characters per byte
#define EXPECTED_KEY_HEX_LENGTH (AEAD_KEY_SIZE * HEX_CHARS_PER_BYTE) // 64 hex chars for 32-byte key
#define SEEK_END_ORIGIN SEEK_END
#define SEEK_SET_ORIGIN SEEK_SET
#define SSCANF_SUCCESS 1
#define FWRITE_SUCCESS 1
#define FREAD_SUCCESS 1

// Command line argument positions
#define ARG_PROGRAM_NAME 0
#define ARG_MODE 1
#define ARG_INPUT_FILE 2
#define ARG_OUTPUT_FILE 3
#define ARG_KEY 4
#define MIN_REQUIRED_ARGS 4
#define ARGS_WITH_KEY 5

// Encrypted file format: [nonce (12 bytes)][ciphertext (variable)][tag (16 bytes)]
#define AEAD_OVERHEAD_SIZE (AEAD_NONCE_SIZE + AEAD_TAG_SIZE)

// ANSI color codes and symbols
#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_BLUE "\x1b[34m"
#define ANSI_COLOR_RESET "\x1b[0m"

#define SYMBOL_SUCCESS "✓"
#define SYMBOL_ERROR "❌"
#define SYMBOL_LOCK "🔒"
#define SYMBOL_UNLOCK "🔓"

// Error handling macros
#define CHECK(condition, context, message) \
    do                                     \
    {                                      \
        if (!(condition))                  \
        {                                  \
            print_error(context, message); \
            return RESULT_ERROR;           \
        }                                  \
    } while (0)

#define CHECK_CLEANUP(condition, context, message, cleanup_func, res) \
    do                                                                \
    {                                                                 \
        if (!(condition))                                             \
        {                                                             \
            print_error(context, message);                            \
            cleanup_func(res);                                        \
            return RESULT_ERROR;                                      \
        }                                                             \
    } while (0)

// Result type definition
typedef enum
{
    RESULT_SUCCESS = 0,
    RESULT_ERROR = -1,
    RESULT_AUTH_FAILED = -2
} result_t;

// Operation mode configuration
typedef struct
{
    const char *name;
    const char *symbol;
    result_t (*handler)(const char *, const char *, const char *);
} operation_mode_t;

// Resource management
typedef struct
{
    FILE *input;
    FILE *output;
    aead_stream_ctx *ctx;
    uint8_t *input_buffer;
    uint8_t *output_buffer;
} file_resources_t;

static void cleanup_resources(file_resources_t *res)
{
    if (res->input)
        fclose(res->input);
    if (res->output)
        fclose(res->output);
    if (res->ctx)
        aead_stream_free(res->ctx);
    if (res->input_buffer)
        free(res->input_buffer);
    if (res->output_buffer)
        free(res->output_buffer);
}

// Progress display helper
static void show_progress(size_t processed_bytes, const char *operation)
{
    static size_t last_shown = 0;
    static const char *last_operation = NULL;

    // Reset progress if operation changes
    if (last_operation != operation)
    {
        last_shown = 0;
        last_operation = operation;
    }

    if (processed_bytes - last_shown >= PROGRESS_INTERVAL || processed_bytes == 0)
    {
        printf("\r%s %s: %zu KB", SYMBOL_LOCK, operation, processed_bytes / PROGRESS_DISPLAY_THRESHOLD);
        fflush(stdout);
        last_shown = processed_bytes;
    }
}

static void print_error(const char *context, const char *message)
{
    fprintf(stderr, ANSI_COLOR_RED "%s Error in %s: %s" ANSI_COLOR_RESET "\n",
            SYMBOL_ERROR, context, message);
}

static void print_success(const char *operation, size_t bytes_processed)
{
    printf("\n" ANSI_COLOR_GREEN "%s %s complete! Processed %zu bytes" ANSI_COLOR_RESET "\n",
           SYMBOL_SUCCESS, operation, bytes_processed);
}

// Initialize file resources
static result_t init_file_resources(file_resources_t *res, const char *input_file,
                                    const char *output_file, const char *context)
{
    memset(res, 0, sizeof(file_resources_t));

    res->input = fopen(input_file, "rb");
    CHECK(res->input, context, "Cannot open input file");

    res->output = fopen(output_file, "wb");
    CHECK_CLEANUP(res->output, context, "Cannot create output file", cleanup_resources, res);

    res->input_buffer = malloc(BUFFER_SIZE);
    res->output_buffer = malloc(BUFFER_SIZE);
    CHECK_CLEANUP(res->input_buffer && res->output_buffer, context,
                  "Memory allocation failed", cleanup_resources, res);

    return RESULT_SUCCESS;
}

// Common streaming processing loop
static result_t process_stream_data(file_resources_t *res, aead_stream_ctx *ctx,
                                    size_t total_size, const char *operation,
                                    bool (*update_func)(aead_stream_ctx *, const uint8_t *, size_t, uint8_t *))
{
    size_t total_processed = 0;
    size_t bytes_read;

    while (total_processed < total_size)
    {
        size_t to_read = (total_size - total_processed < BUFFER_SIZE)
                             ? total_size - total_processed
                             : BUFFER_SIZE;

        bytes_read = fread(res->input_buffer, 1, to_read, res->input);
        if (bytes_read == 0)
            break;

        if (!update_func(ctx, res->input_buffer, bytes_read, res->output_buffer))
        {
            print_error(operation, "Processing failed");
            return RESULT_ERROR;
        }

        if (fwrite(res->output_buffer, 1, bytes_read, res->output) != bytes_read)
        {
            print_error(operation, "Write operation failed");
            return RESULT_ERROR;
        }

        total_processed += bytes_read;
        show_progress(total_processed, operation);
    }

    return RESULT_SUCCESS;
}

// Get file size
static long get_file_size(FILE *file)
{
    fseek(file, 0, SEEK_END_ORIGIN);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET_ORIGIN);
    return size;
}

static result_t read_file_metadata(FILE *file, long file_size, uint8_t *nonce, uint8_t *tag, const char *context)
{
    CHECK(file_size >= AEAD_OVERHEAD_SIZE, context, "File too small - not a valid encrypted file");

    CHECK(fread(nonce, 1, AEAD_NONCE_SIZE, file) == AEAD_NONCE_SIZE,
          context, "Cannot read nonce - file may be corrupted");

    CHECK(fseek(file, file_size - AEAD_TAG_SIZE, SEEK_SET_ORIGIN) == 0 &&
              fread(tag, 1, AEAD_TAG_SIZE, file) == AEAD_TAG_SIZE,
          context, "Cannot read authentication tag - file may be corrupted");

    return RESULT_SUCCESS;
}
// Parse hexadecimal key string
static result_t parse_key_hex(const char *hex_str, uint8_t *key)
{
    CHECK(strlen(hex_str) == EXPECTED_KEY_HEX_LENGTH, "Key parsing",
          "Key must be exactly 64 hex characters (32 bytes)");

    for (size_t i = 0; i < AEAD_KEY_SIZE; i++)
    {
        CHECK(sscanf(hex_str + i * HEX_CHARS_PER_BYTE, "%2hhx", &key[i]) == SSCANF_SUCCESS, "Key parsing",
              "Invalid hex character in key");
    }

    return RESULT_SUCCESS;
}

// Print hex string with formatting
static void print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
}

// Streamlined encrypt
static result_t encrypt_file(const char *input_file, const char *output_file,
                             const uint8_t *key, const uint8_t *nonce)
{
    file_resources_t res;
    const char *context = "Sealing";

    CHECK(init_file_resources(&res, input_file, output_file, context) == RESULT_SUCCESS,
          context, "Failed to initialize resources");

    // Write nonce header and initialize AEAD
    CHECK_CLEANUP(fwrite(nonce, 1, AEAD_NONCE_SIZE, res.output) == AEAD_NONCE_SIZE,
                  context, "Failed to write nonce", cleanup_resources, &res);

    res.ctx = aead_stream_new();
    CHECK_CLEANUP(res.ctx && aead_stream_seal_init(res.ctx, key, nonce, NULL, 0),
                  context, "Failed to initialize AEAD sealing", cleanup_resources, &res);

    // Process file data
    long file_size = get_file_size(res.input);
    result_t result = process_stream_data(&res, res.ctx, file_size, context, aead_stream_seal_update);

    if (result == RESULT_SUCCESS)
    {
        uint8_t tag[AEAD_TAG_SIZE];
        if (aead_stream_seal_final(res.ctx, tag) &&
            fwrite(tag, 1, AEAD_TAG_SIZE, res.output) == AEAD_TAG_SIZE)
        {
            print_success("Sealing", file_size);
        }
        else
        {
            print_error(context, "Failed to finalize sealing or write tag");
            result = RESULT_ERROR;
        }
    }

    cleanup_resources(&res);
    return result;
}

// Streamlined decrypt
static result_t decrypt_file(const char *input_file, const char *output_file,
                             const uint8_t *key)
{
    file_resources_t res;
    const char *context = "Opening";
    uint8_t nonce[AEAD_NONCE_SIZE], stored_tag[AEAD_TAG_SIZE];

    CHECK(init_file_resources(&res, input_file, output_file, context) == RESULT_SUCCESS,
          context, "Failed to initialize resources");

    long file_size = get_file_size(res.input);
    CHECK_CLEANUP(read_file_metadata(res.input, file_size, nonce, stored_tag, context) == RESULT_SUCCESS,
                  context, "Failed to read file metadata", cleanup_resources, &res);

    // Position for ciphertext and initialize AEAD
    size_t ciphertext_size = file_size - AEAD_OVERHEAD_SIZE;
    fseek(res.input, AEAD_NONCE_SIZE, SEEK_SET_ORIGIN);

    res.ctx = aead_stream_new();
    CHECK_CLEANUP(res.ctx && aead_stream_open_init(res.ctx, key, nonce, NULL, 0),
                  context, "Failed to initialize AEAD opening", cleanup_resources, &res);

    // Process and verify
    printf("%s Opening in progress...\n", SYMBOL_UNLOCK);
    result_t result = process_stream_data(&res, res.ctx, ciphertext_size, context, aead_stream_open_update);

    if (result == RESULT_SUCCESS)
    {
        if (aead_stream_open_final(res.ctx, stored_tag))
        {
            printf("\n" ANSI_COLOR_GREEN "%s Authentication verified!" ANSI_COLOR_RESET "\n", SYMBOL_SUCCESS);
            print_success("Opening", ciphertext_size);
        }
        else
        {
            print_error("Authentication", "Verification failed - wrong key or corrupted file");
            fprintf(stderr, ANSI_COLOR_RED "Possible causes: wrong key, corruption, or different tool" ANSI_COLOR_RESET "\n");
            result = RESULT_AUTH_FAILED;
            unlink(output_file);
        }
    }
    else
    {
        unlink(output_file);
    }

    cleanup_resources(&res);
    return result;
}

static void print_usage(const char *program)
{
    printf(ANSI_COLOR_BLUE "🔐 Vault - ChaCha20-Poly1305 AEAD File Encryption Tool" ANSI_COLOR_RESET "\n");

    printf(ANSI_COLOR_YELLOW "USAGE:" ANSI_COLOR_RESET "\n");
    printf("  %s Seal:%s %s -s <input> <output> [key]\n", SYMBOL_LOCK, ANSI_COLOR_RESET, program);
    printf("  %s Open:%s %s -o <input> <output> <key>\n", SYMBOL_UNLOCK, ANSI_COLOR_RESET, program);

    printf(ANSI_COLOR_YELLOW "OPTIONS:" ANSI_COLOR_RESET "\n");
    printf("  -s    Seal (encrypts file, generates random key if not provided)\n");
    printf("  -o    Open (decrypts file, requires key)\n");

    printf(ANSI_COLOR_YELLOW "EXAMPLES:" ANSI_COLOR_RESET "\n");
    printf(" vault -s document.pdf document.enc\n");
    printf(" vault -o document.enc document.pdf a1b2c3d4e5f6789...\n");
}

// Handle sealing operation
static result_t handle_seal(const char *input_file, const char *output_file,
                            const char *key_str)
{
    uint8_t key[AEAD_KEY_SIZE];
    uint8_t nonce[AEAD_NONCE_SIZE];

    if (key_str)
    {
        if (parse_key_hex(key_str, key) != RESULT_SUCCESS)
            return RESULT_ERROR;
    }
    else
    {
        if (!chacha20_keygen(key))
        {
            print_error("Key generation", "Failed to generate random key");
            return RESULT_ERROR;
        }
        printf(ANSI_COLOR_RED "Key: ");
        print_hex(key, AEAD_KEY_SIZE);
        printf("\nSave this key - it's required for decryption!" ANSI_COLOR_RESET "\n\n");
    }

    if (!chacha20_noncegen(nonce))
    {
        print_error("Nonce generation", "Failed to generate random nonce");
        return RESULT_ERROR;
    }

    printf("%s Sealing: %s → %s\n", SYMBOL_LOCK, input_file, output_file);
    return encrypt_file(input_file, output_file, key, nonce);
}

// Handle opening operation
static result_t handle_open(const char *input_file, const char *output_file,
                            const char *key_str)
{
    if (!key_str)
    {
        print_error("Input validation", "Opening requires a key");
        return RESULT_ERROR;
    }

    uint8_t key[AEAD_KEY_SIZE];
    if (parse_key_hex(key_str, key) != RESULT_SUCCESS)
        return RESULT_ERROR;

    printf("%s Opening: %s → %s\n", SYMBOL_UNLOCK, input_file, output_file);
    return decrypt_file(input_file, output_file, key);
}

static const operation_mode_t modes[] = {
    {"-s", SYMBOL_LOCK, handle_seal},
    {"-o", SYMBOL_UNLOCK, handle_open},
    {NULL, NULL, NULL} // Sentinel
};

static const operation_mode_t *find_mode(const char *mode_str)
{
    for (const operation_mode_t *mode = modes; mode->name; mode++)
    {
        if (strcmp(mode_str, mode->name) == 0)
            return mode;
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    if (argc < MIN_REQUIRED_ARGS)
    {
        print_usage(argv[ARG_PROGRAM_NAME]);
        return EXIT_FAILURE;
    }

    const char *mode_str = argv[ARG_MODE];
    const char *input_file = argv[ARG_INPUT_FILE];
    const char *output_file = argv[ARG_OUTPUT_FILE];
    const char *key_str = (argc >= ARGS_WITH_KEY) ? argv[ARG_KEY] : NULL;

    const operation_mode_t *mode = find_mode(mode_str);
    if (!mode)
    {
        print_error("Command line", "Invalid mode - use -s for sealing or -o for opening");
        print_usage(argv[ARG_PROGRAM_NAME]);
        return EXIT_FAILURE;
    }

    result_t result = mode->handler(input_file, output_file, key_str);

    if (result != RESULT_SUCCESS)
        printf("\n" ANSI_COLOR_RED "%s Operation failed!" ANSI_COLOR_RESET "\n", SYMBOL_ERROR);

    return (result == RESULT_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}
