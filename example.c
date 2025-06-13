#include "src/chacha20.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    // Key and nonce (should be randomly generated in practice)
    uint8_t key[32] = "this_is_a_32_byte_key_for_demo!!";
    uint8_t nonce[12] = "demo_nonce12";

    const char *message = "🤓 This is a test message for ChaCha20 encryption!";
    size_t msg_len = strlen(message);

    // Create context
    chacha20_ctx *ctx = chacha20_new();
    if (!ctx)
        return -1;

    // Initialize
    chacha20_init(ctx, key, nonce, 0);

    // Encrypt
    uint8_t ciphertext[256];
    chacha20_encrypt(ctx, (uint8_t *)message, ciphertext, msg_len);

    // Print encrypted data in hex
    printf("Original:  %s\n", message);
    printf("Encrypted: ");
    for (size_t i = 0; i < msg_len; i++)
    {
        printf("%02x", ciphertext[i]);
        if (i % 4 == 3)
            printf(" ");
    }
    printf("\n");

    // Decrypt
    chacha20_reset_counter(ctx, 0);
    uint8_t decrypted[256];
    chacha20_decrypt(ctx, ciphertext, decrypted, msg_len);
    decrypted[msg_len] = '\0';

    printf("Decrypted: %s\n", decrypted);

    // Clean up
    chacha20_free(ctx);
    return 0;
}
