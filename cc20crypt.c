#include "src/chacha20.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define BUFFER_SIZE 8192
#define PROGRESS_INTERVAL (BUFFER_SIZE * 10)

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_RESET "\x1b[0m"

typedef enum
{
    RESULT_SUCCESS = 0,
    RESULT_ERROR = -1
} result_t;

// Generate cryptographically secure random bytes
static result_t generate_random_bytes(uint8_t *buffer, size_t length)
{
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (!urandom)
    {
        fprintf(stderr, "Error: Cannot access /dev/urandom: %s\n", strerror(errno));
        return RESULT_ERROR;
    }

    if (fread(buffer, 1, length, urandom) != length)
    {
        fprintf(stderr, "Error: Failed to read %zu random bytes\n", length);
        fclose(urandom);
        return RESULT_ERROR;
    }

    fclose(urandom);
    return RESULT_SUCCESS;
}

// Process file with ChaCha20 cipher
static result_t process_file_data(chacha20_ctx *ctx, FILE *in, FILE *out, const char *operation)
{
    uint8_t *input_buffer = malloc(BUFFER_SIZE);
    uint8_t *output_buffer = malloc(BUFFER_SIZE);

    if (!input_buffer || !output_buffer)
    {
        fprintf(stderr, "Error: Memory allocation failed\n");
        free(input_buffer);
        free(output_buffer);
        return RESULT_ERROR;
    }

    size_t total_bytes = 0;
    size_t bytes_read;

    while ((bytes_read = fread(input_buffer, 1, BUFFER_SIZE, in)) > 0)
    {
        chacha20_encrypt(ctx, input_buffer, output_buffer, bytes_read);

        if (fwrite(output_buffer, 1, bytes_read, out) != bytes_read)
        {
            fprintf(stderr, "Error: Write operation failed\n");
            free(input_buffer);
            free(output_buffer);
            return RESULT_ERROR;
        }

        total_bytes += bytes_read;

        if (total_bytes % PROGRESS_INTERVAL == 0)
        {
            printf("%s: %zu KB\r", operation, total_bytes / 1024);
            fflush(stdout);
        }
    }

    printf("\n%s complete! Processed %zu bytes\n", operation, total_bytes);

    free(input_buffer);
    free(output_buffer);
    return RESULT_SUCCESS;
}

// Encrypt file with ChaCha20
static result_t encrypt_file(const char *input_file, const char *output_file,
                             const uint8_t *key, const uint8_t *nonce)
{
    FILE *in = fopen(input_file, "rb");
    if (!in)
    {
        fprintf(stderr, "Error: Cannot open input file '%s': %s\n",
                input_file, strerror(errno));
        return RESULT_ERROR;
    }

    FILE *out = fopen(output_file, "wb");
    if (!out)
    {
        fprintf(stderr, "Error: Cannot create output file '%s': %s\n",
                output_file, strerror(errno));
        fclose(in);
        return RESULT_ERROR;
    }

    chacha20_ctx *ctx = chacha20_new();
    if (!ctx)
    {
        fprintf(stderr, "Error: Failed to create encryption context\n");
        fclose(in);
        fclose(out);
        return RESULT_ERROR;
    }

    chacha20_init(ctx, key, nonce, 0);

    // Write nonce to file header for decryption
    if (fwrite(nonce, 1, CHACHA20_NONCE_SIZE, out) != CHACHA20_NONCE_SIZE)
    {
        fprintf(stderr, "Error: Failed to write nonce to output file\n");
        chacha20_free(ctx);
        fclose(in);
        fclose(out);
        return RESULT_ERROR;
    }

    result_t result = process_file_data(ctx, in, out, "Encrypted");

    chacha20_free(ctx);
    fclose(in);
    fclose(out);
    return result;
}

// Decrypt file with ChaCha20
static result_t decrypt_file(const char *input_file, const char *output_file,
                             const uint8_t *key)
{
    FILE *in = fopen(input_file, "rb");
    if (!in)
    {
        fprintf(stderr, "Error: Cannot open input file '%s': %s\n",
                input_file, strerror(errno));
        return RESULT_ERROR;
    }

    FILE *out = fopen(output_file, "wb");
    if (!out)
    {
        fprintf(stderr, "Error: Cannot create output file '%s': %s\n",
                output_file, strerror(errno));
        fclose(in);
        return RESULT_ERROR;
    }

    // Read nonce from file header
    uint8_t nonce[CHACHA20_NONCE_SIZE];
    if (fread(nonce, 1, CHACHA20_NONCE_SIZE, in) != CHACHA20_NONCE_SIZE)
    {
        fprintf(stderr, "Error: Cannot read nonce - file may be corrupted\n");
        fclose(in);
        fclose(out);
        return RESULT_ERROR;
    }

    chacha20_ctx *ctx = chacha20_new();
    if (!ctx)
    {
        fprintf(stderr, "Error: Failed to create decryption context\n");
        fclose(in);
        fclose(out);
        return RESULT_ERROR;
    }

    chacha20_init(ctx, key, nonce, 0);
    result_t result = process_file_data(ctx, in, out, "Decrypted");

    chacha20_free(ctx);
    fclose(in);
    fclose(out);
    return result;
}

// Parse hexadecimal key string
static result_t parse_key_hex(const char *hex_str, uint8_t *key)
{
    const size_t expected_len = CHACHA20_KEY_SIZE * 2;

    if (strlen(hex_str) != expected_len)
    {
        fprintf(stderr, "Error: Key must be exactly %zu hex characters (%d bytes)\n",
                expected_len, CHACHA20_KEY_SIZE);
        return RESULT_ERROR;
    }

    for (size_t i = 0; i < CHACHA20_KEY_SIZE; i++)
    {
        if (sscanf(hex_str + i * 2, "%2hhx", &key[i]) != 1)
        {
            fprintf(stderr, "Error: Invalid hex character at position %zu\n", i * 2);
            return RESULT_ERROR;
        }
    }

    return RESULT_SUCCESS;
}

static void print_usage(const char *program)
{
    printf("CC20Crypt - ChaCha20 File Encryption Tool\n\n");
    printf("USAGE:\n");
    printf("  Encrypt: %s -e <input> <output> [key]\n", program);
    printf("  Decrypt: %s -d <input> <output> <key>\n", program);
    printf("\n");
    printf("OPTIONS:\n");
    printf("  -e    Encrypt mode (generates random key if not provided)\n");
    printf("  -d    Decrypt mode (requires key)\n");
    printf("\n");
    printf("KEY FORMAT:\n");
    printf("  64 hexadecimal characters (256-bit key)\n");
    printf("\n");
    printf("EXAMPLES:\n");
    printf("  cc20crypt -e file.txt file.enc\n");
    printf("  cc20crypt -d file.enc file.txt a1b2c3d4e5f6789...\n");
}

// Handle encryption operation
static result_t handle_encrypt(const char *input_file, const char *output_file,
                               const char *key_str)
{
    uint8_t key[CHACHA20_KEY_SIZE];
    uint8_t nonce[CHACHA20_NONCE_SIZE];

    if (key_str)
    {
        if (parse_key_hex(key_str, key) != RESULT_SUCCESS)
            return RESULT_ERROR;
    }
    else
    {
        if (generate_random_bytes(key, CHACHA20_KEY_SIZE) != RESULT_SUCCESS)
            return RESULT_ERROR;
        printf("Generated key:\n");
        printf(ANSI_COLOR_RED "Key (hex): ");
        for (size_t i = 0; i < CHACHA20_KEY_SIZE; i++)
            printf("%02x", key[i]);
        printf("\n⚠️  Save this key - it's required for decryption!" ANSI_COLOR_RESET "\n\n");
    }

    if (generate_random_bytes(nonce, CHACHA20_NONCE_SIZE) != RESULT_SUCCESS)
        return RESULT_ERROR;

    printf("Encrypting: %s → %s\n", input_file, output_file);
    return encrypt_file(input_file, output_file, key, nonce);
}

// Handle decryption operation
static result_t handle_decrypt(const char *input_file, const char *output_file,
                               const char *key_str)
{
    if (!key_str)
    {
        fprintf(stderr, "Error: Decryption requires a key\n");
        return RESULT_ERROR;
    }

    uint8_t key[CHACHA20_KEY_SIZE];
    if (parse_key_hex(key_str, key) != RESULT_SUCCESS)
        return RESULT_ERROR;

    printf("Decrypting: %s → %s\n", input_file, output_file);
    return decrypt_file(input_file, output_file, key);
}

int main(int argc, char *argv[])
{
    if (argc < 4)
    {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *mode = argv[1];
    const char *input_file = argv[2];
    const char *output_file = argv[3];
    const char *key_str = (argc >= 5) ? argv[4] : NULL;

    result_t result;

    if (strcmp(mode, "-e") == 0)
    {
        result = handle_encrypt(input_file, output_file, key_str);
    }
    else if (strcmp(mode, "-d") == 0)
    {
        result = handle_decrypt(input_file, output_file, key_str);
    }
    else
    {
        fprintf(stderr, "Error: Invalid mode '%s'\n\n", mode);
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    return (result == RESULT_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}
