#include "src/aead.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFFER_SIZE 8192
#define EXPECTED_KEY_HEX_LENGTH (AEAD_KEY_SIZE * 2)
#define MIN_REQUIRED_ARGS 4
#define ARGS_WITH_KEY 5
#define AEAD_OVERHEAD_SIZE (AEAD_NONCE_SIZE + AEAD_TAG_SIZE)

// Command line argument positions
enum
{
    ARG_PROGRAM_NAME = 0,
    ARG_MODE = 1,
    ARG_INPUT_FILE = 2,
    ARG_OUTPUT_FILE = 3,
    ARG_KEY = 4
};

// UI styling
#define COLOR_RED "\x1b[31m"
#define COLOR_GREEN "\x1b[32m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_BLUE "\x1b[34m"
#define COLOR_RESET "\x1b[0m"

#define SYMBOL_SUCCESS "✓"
#define SYMBOL_ERROR "✗"
#define SYMBOL_LOCK "🔒"
#define SYMBOL_UNLOCK "🔓"

// Result and error handling
typedef enum
{
    RESULT_SUCCESS = 0,
    RESULT_ERROR = -1,
    RESULT_AUTH_FAILED = -2
} result_t;

static void print_error(const char *message)
{
    fprintf(stderr, COLOR_RED "%s %s" COLOR_RESET "\n", SYMBOL_ERROR, message);
}

#define FAIL_IF(condition, message) \
    do                              \
    {                               \
        if (condition)              \
        {                           \
            print_error(message);   \
            return RESULT_ERROR;    \
        }                           \
    } while (0)

#define FAIL_IF_CLEANUP(condition, message, cleanup, res) \
    do                                                    \
    {                                                     \
        if (condition)                                    \
        {                                                 \
            print_error(message);                         \
            cleanup(res);                                 \
            return RESULT_ERROR;                          \
        }                                                 \
    } while (0)

// File processing resources
typedef struct
{
    FILE *input, *output;
    aead_stream_ctx *ctx;
    uint8_t *input_buffer, *output_buffer;
} resources_t;

static void cleanup_resources(resources_t *res)
{
    if (res->input)
        fclose(res->input);
    if (res->output)
        fclose(res->output);
    if (res->ctx)
        aead_stream_free(res->ctx);
    free(res->input_buffer);
    free(res->output_buffer);
}

static void format_size(size_t bytes, char *buffer, size_t buffer_size)
{
    if (bytes >= 1024ULL * 1024 * 1024)
        snprintf(buffer, buffer_size, "%.2f GB", (double)bytes / (1024ULL * 1024 * 1024));
    else if (bytes >= 1024 * 1024)
        snprintf(buffer, buffer_size, "%.2f MB", (double)bytes / (1024 * 1024));
    else if (bytes >= 1024)
        snprintf(buffer, buffer_size, "%.2f KB", (double)bytes / 1024);
    else
        snprintf(buffer, buffer_size, "%zu bytes", bytes);
}

static void print_success(const char *op, size_t bytes)
{
    char size_str[32];
    format_size(bytes, size_str, sizeof(size_str));
    printf(COLOR_GREEN "%s %s complete! Processed %s" COLOR_RESET "\n",
           SYMBOL_SUCCESS, op, size_str);
}

// Initialize file resources
static result_t init_file_resources(resources_t *res, const char *input_file,
                                    const char *output_file)
{
    memset(res, 0, sizeof(resources_t));

    FAIL_IF(!(res->input = fopen(input_file, "rb")), "Cannot open input file");
    FAIL_IF_CLEANUP(!(res->output = fopen(output_file, "wb")),
                    "Cannot create output file", cleanup_resources, res);

    res->input_buffer = malloc(BUFFER_SIZE);
    res->output_buffer = malloc(BUFFER_SIZE);
    FAIL_IF_CLEANUP(!res->input_buffer || !res->output_buffer,
                    "Memory allocation failed", cleanup_resources, res);

    return RESULT_SUCCESS;
}

// Common streaming processing loop
static result_t process_stream_data(resources_t *res, size_t total_size,
                                    bool (*update_func)(aead_stream_ctx *, const uint8_t *, size_t, uint8_t *))
{
    size_t total_processed = 0;

    while (total_processed < total_size)
    {
        size_t to_read = (total_size - total_processed < BUFFER_SIZE)
                             ? total_size - total_processed
                             : BUFFER_SIZE;

        size_t bytes_read = fread(res->input_buffer, 1, to_read, res->input);
        if (bytes_read == 0)
            break;

        FAIL_IF(!update_func(res->ctx, res->input_buffer, bytes_read, res->output_buffer),
                "Processing failed");

        FAIL_IF(fwrite(res->output_buffer, 1, bytes_read, res->output) != bytes_read,
                "Write operation failed");

        total_processed += bytes_read;
    }

    return RESULT_SUCCESS;
}

// Get file size
static size_t get_file_size(FILE *file)
{
    if (fseek(file, 0, SEEK_END) != 0)
        return 0;
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    return (size >= 0) ? (size_t)size : 0;
}

static result_t read_file_metadata(FILE *file, size_t file_size, uint8_t *nonce, uint8_t *tag)
{
    FAIL_IF(file_size < AEAD_OVERHEAD_SIZE, "File too small - not a valid encrypted file");
    FAIL_IF(fread(nonce, 1, AEAD_NONCE_SIZE, file) != AEAD_NONCE_SIZE,
            "Cannot read nonce - file may be corrupted");
    FAIL_IF(fseek(file, file_size - AEAD_TAG_SIZE, SEEK_SET) != 0 ||
                fread(tag, 1, AEAD_TAG_SIZE, file) != AEAD_TAG_SIZE,
            "Cannot read authentication tag - file may be corrupted");
    return RESULT_SUCCESS;
}
// Parse hexadecimal key string
static result_t parse_key_hex(const char *hex_str, uint8_t *key)
{
    FAIL_IF(strlen(hex_str) != EXPECTED_KEY_HEX_LENGTH,
            "Key must be exactly 64 hex characters (32 bytes)");

    for (size_t i = 0; i < AEAD_KEY_SIZE; i++)
    {
        FAIL_IF(sscanf(hex_str + i * 2, "%2hhx", &key[i]) != 1,
                "Invalid hex character in key");
    }
    return RESULT_SUCCESS;
}

// Encrypt file with streaming AEAD
static result_t encrypt_file(const char *input_file, const char *output_file,
                             const uint8_t *key, const uint8_t *nonce)
{
    resources_t res;
    FAIL_IF(init_file_resources(&res, input_file, output_file) != RESULT_SUCCESS,
            "Failed to initialize resources");

    // Write nonce header and initialize AEAD
    FAIL_IF_CLEANUP(fwrite(nonce, 1, AEAD_NONCE_SIZE, res.output) != AEAD_NONCE_SIZE,
                    "Failed to write nonce", cleanup_resources, &res);

    res.ctx = aead_stream_new();
    FAIL_IF_CLEANUP(!res.ctx || !aead_stream_seal_init(res.ctx, key, nonce, NULL, 0),
                    "Failed to initialize AEAD sealing", cleanup_resources, &res);

    // Process file data
    size_t file_size = get_file_size(res.input);
    result_t result = process_stream_data(&res, file_size, aead_stream_seal_update);

    if (result == RESULT_SUCCESS)
    {
        uint8_t tag[AEAD_TAG_SIZE];
        if (aead_stream_seal_final(res.ctx, tag) &&
            fwrite(tag, 1, AEAD_TAG_SIZE, res.output) == AEAD_TAG_SIZE)
            print_success("Sealing", file_size);
        else
        {
            print_error("Failed to finalize sealing");
            result = RESULT_ERROR;
        }
    }

    cleanup_resources(&res);
    return result;
}

// Decrypt file with streaming AEAD
static result_t decrypt_file(const char *input_file, const char *output_file,
                             const uint8_t *key)
{
    resources_t res;
    uint8_t nonce[AEAD_NONCE_SIZE], stored_tag[AEAD_TAG_SIZE];

    FAIL_IF(init_file_resources(&res, input_file, output_file) != RESULT_SUCCESS,
            "Failed to initialize resources");

    size_t file_size = get_file_size(res.input);
    FAIL_IF_CLEANUP(read_file_metadata(res.input, file_size, nonce, stored_tag) != RESULT_SUCCESS,
                    "Failed to read file metadata", cleanup_resources, &res);

    // Position for ciphertext and initialize AEAD
    size_t ciphertext_size = file_size - AEAD_OVERHEAD_SIZE;
    fseek(res.input, AEAD_NONCE_SIZE, SEEK_SET);

    res.ctx = aead_stream_new();
    FAIL_IF_CLEANUP(!res.ctx || !aead_stream_open_init(res.ctx, key, nonce, NULL, 0),
                    "Failed to initialize AEAD opening", cleanup_resources, &res);

    // Process and verify
    result_t result = process_stream_data(&res, ciphertext_size, aead_stream_open_update);

    if (result == RESULT_SUCCESS)
    {
        if (aead_stream_open_final(res.ctx, stored_tag))
        {
            printf("\n" COLOR_GREEN "%s Authentication verified!" COLOR_RESET "\n", SYMBOL_SUCCESS);
            print_success("Opening", ciphertext_size);
        }
        else
        {
            print_error("Verification failed - wrong key or corrupted file");
            fprintf(stderr, COLOR_RED "Possible causes: wrong key, corruption, or different tool" COLOR_RESET "\n");
            result = RESULT_AUTH_FAILED;
            unlink(output_file);
        }
    }
    else
        unlink(output_file);

    cleanup_resources(&res);
    return result;
}

static void print_usage(const char *program)
{
    printf(COLOR_BLUE "🔐 Vault - ChaCha20-Poly1305 AEAD File Encryption Tool" COLOR_RESET "\n");

    printf(COLOR_YELLOW "USAGE:" COLOR_RESET "\n");
    printf("  %s Seal:  %s -s <input> <output> [key]\n", SYMBOL_LOCK, program);
    printf("  %s Open:  %s -o <input> <output> <key>\n", SYMBOL_UNLOCK, program);

    printf(COLOR_YELLOW "OPTIONS:" COLOR_RESET "\n");
    printf("  -s    Seal (encrypt and authenticate file, generates random key if not provided)\n");
    printf("  -o    Open (decrypt file and verify authentication tag, requires key)\n");

    printf(COLOR_YELLOW "EXAMPLES:" COLOR_RESET "\n");
    printf("  %s -s document.pdf document.enc\n", program);
    printf("  %s -o document.enc document.pdf a1b2c3d4e5f6789...\n", program);
}

// Handle seal operation
static result_t handle_seal(const char *input_file, const char *output_file,
                            const char *key_str)
{
    uint8_t key[AEAD_KEY_SIZE], nonce[AEAD_NONCE_SIZE];

    if (key_str)
        FAIL_IF(parse_key_hex(key_str, key) != RESULT_SUCCESS, "Invalid key format");
    else
    {
        FAIL_IF(!aead_keygen(key), "Failed to generate random key");
        printf(COLOR_RED "Key: ");
        for (size_t i = 0; i < AEAD_KEY_SIZE; i++)
            printf("%02x", key[i]);
        printf("\nSave this key - it's required for decryption!" COLOR_RESET "\n\n");
    }

    FAIL_IF(!aead_noncegen(nonce), "Failed to generate random nonce");

    printf("%s Sealing: %s → %s\n", SYMBOL_LOCK, input_file, output_file);
    return encrypt_file(input_file, output_file, key, nonce);
}

// Handle open operation
static result_t handle_open(const char *input_file, const char *output_file,
                            const char *key_str)
{
    FAIL_IF(!key_str, "Opening requires a key");

    uint8_t key[AEAD_KEY_SIZE];
    FAIL_IF(parse_key_hex(key_str, key) != RESULT_SUCCESS, "Invalid key format");

    printf("%s Opening: %s → %s\n", SYMBOL_UNLOCK, input_file, output_file);
    return decrypt_file(input_file, output_file, key);
}

int main(int argc, char *argv[])
{
    if (argc < MIN_REQUIRED_ARGS)
    {
        print_usage(argv[ARG_PROGRAM_NAME]);
        return EXIT_FAILURE;
    }

    const char *mode = argv[ARG_MODE];
    const char *input_file = argv[ARG_INPUT_FILE];
    const char *output_file = argv[ARG_OUTPUT_FILE];
    const char *key_str = (argc >= ARGS_WITH_KEY) ? argv[ARG_KEY] : NULL;

    result_t result;
    if (strcmp(mode, "-s") == 0)
        result = handle_seal(input_file, output_file, key_str);
    else if (strcmp(mode, "-o") == 0)
        result = handle_open(input_file, output_file, key_str);
    else
    {
        print_error("Invalid mode - use -s for sealing or -o for opening");
        print_usage(argv[ARG_PROGRAM_NAME]);
        return EXIT_FAILURE;
    }

    if (result != RESULT_SUCCESS)
        printf("\n" COLOR_RED "%s Operation failed!" COLOR_RESET "\n", SYMBOL_ERROR);

    return (result == RESULT_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}
