# ChaCha20 Cipher Implementation in C

<p align="center">
    <a href="https://opensource.org/licenses/MIT">
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT">
    </a>
    <a href="https://en.wikipedia.org/wiki/C99">
        <img src="https://img.shields.io/badge/C-C99-blue.svg" alt="C Standard">
    </a>
    <a href="https://tools.ietf.org/rfc/rfc7539.txt">
        <img src="https://img.shields.io/badge/RFC%207539-Compliant-green.svg" alt="RFC Compliance">
    </a>
</p>

A complete ChaCha20 stream cipher implementation in C, compliant with RFC 7539 standards.

## Core Components

### 1. ChaCha20 Encryption Library (`src/`)

Core ChaCha20 algorithm implementation:

- **`chacha20.h`** - Public API interface definition
- **`chacha20.c`** - ChaCha20 algorithm core implementation

### 2. CC20Crypt File Encryption Tool (`cc20crypt.c`)

Command-line file encryption tool built on the ChaCha20 library:

- **Automatic Key Generation** - Uses `/dev/urandom` to generate cryptographically secure random keys
- **Stream File Processing** - Efficiently handles files of any size with 8KB buffer
- **Secure Random Numbers** - Automatically generates and manages nonce (number used once)
- **Progress Display** - Real-time encryption/decryption progress

#### Usage

```bash
# Encrypt file (automatically generate random key)
./cc20crypt -e input.txt output.enc

# Encrypt with specified key
./cc20crypt -e input.txt output.enc a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789a

# Decrypt file
./cc20crypt -d output.enc decrypted.txt a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789a
```

### 3. Example Program (`example.c`)

Simple usage example demonstrating basic encryption/decryption operations

### 4. Test Suite (`test_chacha20.c`)

Comprehensive test program ensuring implementation correctness:

- **RFC 7539 Standard Tests** - Validates consistency with official test vectors
- **Basic Functionality Tests** - Tests encryption/decryption cycles
- **Counter Operation Tests** - Validates counter reset functionality
- **Stream Processing Tests** - Tests multi-block message processing
- **Boundary Condition Tests** - Tests special cases like zero-length data

## Project Structure

```
.
├── src/
│   ├── chacha20.h          # ChaCha20 API interface definition
│   └── chacha20.c          # ChaCha20 core algorithm implementation
├── cc20crypt.c             # CC20Crypt file encryption tool source code
├── test_chacha20.c         # Test suite (includes RFC 7539 test vectors)
├── example.c               # Simple usage example
├── Makefile               # Build configuration file
└── README.md              # Project documentation
```

## Build and Run

### Build All Targets

```bash
make all
```

This will build the following programs:

- `test_chacha20` - Test suite
- `example` - Example program
- `cc20crypt` - File encryption tool

### Run Tests

```bash
make test
```

### Clean Build Files

```bash
make clean
```

## ChaCha20 API Reference

### Context Management

```c
#include "src/chacha20.h"

// Create new context
chacha20_ctx *ctx = chacha20_new();

// Free context after use
chacha20_free(ctx);
```

### Initialization

```c
uint8_t key[CHACHA20_KEY_SIZE] = { /* 32-byte key */ };
uint8_t nonce[CHACHA20_NONCE_SIZE] = { /* 12-byte nonce */ };
uint32_t counter = 0; // Counter, usually starts from 0 or 1

chacha20_init(ctx, key, nonce, counter);
```

### Encryption/Decryption Operations

```c
const uint8_t *plaintext = /* input data */;
uint8_t *ciphertext = /* output buffer */;
size_t length = /* data length */;

// Encrypt (ChaCha20 is symmetric, encryption and decryption use the same function)
chacha20_encrypt(ctx, plaintext, ciphertext, length);

// Decrypt
chacha20_decrypt(ctx, ciphertext, plaintext, length);
```

### Example Usage

```c

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
```

> **Security Note**: In production code, consider using `mlock()` to prevent sensitive data (keys, plaintexts) from being swapped to disk. Remember to call `munlock()` before freeing memory and handle potential failures (requires appropriate privileges on some systems).

### Counter Reset

**⚠️ Security Warning**: Counter reset operations require careful consideration to maintain encryption security.

```c
// Reset counter for stream positioning or re-encryption
chacha20_reset_counter(ctx, new_counter_value);
```

**Important Notes:**

- **Never reuse** the same counter value with the same key/nonce pair for different data
- Counter reset is primarily for **stream positioning** (jumping to specific positions in large streams)
- When decrypting, reset counter to the **same value** used during encryption
- For the same key/nonce pair, counter values should be **monotonically increasing**
- When possible, consider using different nonces instead of resetting counters

### Secure Cleanup

```c
// Clear sensitive data from context
chacha20_clear(ctx);
```

## Test Coverage

The test suite includes the following test categories:

### 1. RFC 7539 Standard Compliance Tests

- **Keystream Generation Tests** - Validates ChaCha20 block function
- **Encryption Tests** - Verifies complete encryption/decryption using official test vectors

### 2. Functional Tests

- **Basic Operation Tests** - Basic encryption/decryption cycles
- **Counter Operation Tests** - Counter reset and management
- **Stream Processing Tests** - Multi-block messages and chunked processing

### 3. Boundary and Error Tests

- **Zero-Length Data** - Handling empty data
- **Context Cleanup** - Secure memory clearing
- **Error Handling** - Null pointers and invalid parameters

Run `make test` to execute all tests. All tests must pass to indicate a valid implementation.

## Security Considerations

### 1. Key Management

- Use cryptographically secure random number generators
- Clean key data from memory promptly
- Avoid long-term key persistence in the system

### 2. Nonce Uniqueness

- **Never reuse** nonces with the same key
- Use high-quality random sources (like `/dev/urandom`)
- Ensure statistical quality of nonce distribution

### 3. Counter Management

- Avoid counter overflow for the same key/nonce pair
- Maintain monotonicity when resetting counters
- Consider key rotation for long-term use

### 4. Memory Safety

- Immediately clear sensitive data after use
- Prevent sensitive data from entering swap files
- Consider secure memory allocation

### 5. Side-Channel Protection

- Implementation has constant-time characteristics
- Avoid secret-data-dependent branches
- Consider cache timing attack protection

## Use Cases

ChaCha20 is suitable for the following scenarios:

- **Network Communication Encryption** - High-performance alternative to AES
- **File Encryption** - Stream encryption for large files
- **Stream Data Encryption** - Real-time data stream encryption
- **Embedded Systems** - Encryption needs in resource-constrained environments
- **High-Performance Scenarios** - Where software implementation outperforms AES

## Example Code

### Basic Usage Example

#file:example.c

### Performance Characteristics

- **High Security** - Resistant to differential and linear cryptanalysis
- **High Performance** - Software implementation faster than AES
- **Simple Design** - Easy to implement and verify correctness
- **Side-Channel Resistance** - Designed for constant-time implementation

## License

This implementation is released under the MIT License. Free to use, modify, and distribute.

## References

- [RFC 7539: ChaCha20 and Poly1305 for IETF Protocols](https://tools.ietf.org/rfc/rfc7539.txt)
- [RFC 7905: ChaCha20 and Poly1305 based Cipher Suites for TLS](https://tools.ietf.org/rfc/rfc7905.txt)
- [Daniel J. Bernstein's ChaCha20 specification](https://cr.yp.to/chacha.html)
- [Original ChaCha paper](https://cr.yp.to/chacha/chacha-20080128.pdf)

## Contributing

Contributions welcome! Please ensure:

- All tests pass (`make test`)
- Code follows existing style
- New features include appropriate tests
- Documentation updated accordingly

## TODO

- [ ] ChaCha20-Poly1305 AEAD Support - Add authenticated encryption mode
- [ ] Key Derivation Function - Integrate PBKDF2/Argon2 support for secure key generation

## FAQ

### Q: What advantages does ChaCha20 have over AES?

A: ChaCha20 is typically faster than AES in software implementations, has a simpler design, is easier to implement in constant time, and doesn't require dedicated hardware support.

### Q: Can this implementation be used in production?

A: Yes, this implementation passes all RFC 7539 test vectors, includes comprehensive test coverage, and is suitable for production use. However, independent security auditing is recommended for critical applications.

### Q: How to securely generate keys and nonces?

A: Use cryptographically secure random number generators, such as Linux's `/dev/urandom` or OpenSSL's RAND_bytes(). Never use regular rand() function.

### Q: What happens when the counter overflows?

A: Counter overflow causes keystream repetition, which is insecure. For long-term use, keys should be changed or different nonces should be used.
