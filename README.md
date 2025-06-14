# ChaCha20 Stream Cipher implementation in C

A complete ChaCha20 stream cipher implementation in C, compliant with RFC 7539 standards.

## Core Components

### ChaCha20 Library (`src/`)

Core ChaCha20 algorithm implementation:

- **`chacha20.h`** - API specification and type definitions
- **`chacha20.c`** - Core algorithm implementation

### 2. CC20Crypt File Encryption Tool (`cc20crypt.c`)

Command-line file encryption tool built on the ChaCha20 library:

- **Secure Key Generation** - Uses `/dev/urandom` entropy source
- **Stream Processing** - 8KB buffering for memory efficiency
- **Nonce Management** - Automatic unique nonce generation

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

- **RFC 7539 Compliance** - Official test vector validation
- **Functional Testing** - Operational integrity verification
- **Boundary Testing** - Edge cases and error handling
- **Performance Testing** - Complexity validation

## Project Structure

```
.
├── src/
│   ├── chacha20.h          # API specification
│   └── chacha20.c          # Core implementation
├── cc20crypt.c             # File encryption utility
├── test_chacha20.c         # Test suite
├── example.c               # Usage examples
├── Makefile               # Build configuration
└── README.md              # Documentation
```

## Mathematical Foundation and Algorithmic Analysis

### State Matrix Representation

The ChaCha20 algorithm operates on a 4×4 state matrix $\mathbf{S}$, where each element represents a 32-bit word. The initial state configuration follows the standardized construction:

$$
\mathbf{S}_{\text{initial}} = \begin{bmatrix}
\text{0x61707865} & \text{0x3320646e} & \text{0x79622d32} & \text{0x6b206574} \\
k_0 & k_1 & k_2 & k_3 \\
k_4 & k_5 & k_6 & k_7 \\
\text{counter} & n_0 & n_1 & n_2
\end{bmatrix}
$$

Where the constituent elements are defined as:

- Row 0: ASCII encoding of "expand 32-byte k" (constant values)
- Rows 1-2: 256-bit key $K$ partitioned into eight 32-bit words $k_i$
- Row 3: 32-bit block counter and 96-bit nonce $N$ partitioned into three 32-bit words $n_i$

### Quarter Round Primitive Operation

The fundamental computational unit is the quarter round function $QR(a,b,c,d)$, operating on four 32-bit words with the following transformation sequence:

$$
\begin{align}
a &\leftarrow a + b; \quad d \leftarrow (d \oplus a) \lll 16 \\
c &\leftarrow c + d; \quad b \leftarrow (b \oplus c) \lll 12 \\
a &\leftarrow a + b; \quad d \leftarrow (d \oplus a) \lll 8 \\
c &\leftarrow c + d; \quad b \leftarrow (b \oplus c) \lll 7
\end{align}
$$

### Block Transformation Function

Each ChaCha20 block undergoes 20 rounds of transformations, organized as 10 double rounds. Each double round consists of:

**Column Round Operations:**
$$QR(S_0, S_4, S_8, S_{12}), QR(S_1, S_5, S_9, S_{13}), QR(S_2, S_6, S_{10}, S_{14}), QR(S_3, S_7, S_{11}, S_{15})$$

**Diagonal Round Operations:**
$$QR(S_0, S_5, S_{10}, S_{15}), QR(S_1, S_6, S_{11}, S_{12}), QR(S_2, S_7, S_8, S_{13}), QR(S_3, S_4, S_9, S_{14})$$

The complete block transformation follows this procedure:

1. **State Initialization**: $\mathbf{W} \leftarrow \mathbf{S}_{\text{initial}}$
2. **Round Processing**: Apply 10 double rounds to $\mathbf{W}$
3. **State Addition**: $\mathbf{W} \leftarrow \mathbf{W} + \mathbf{S}_{\text{initial}}$
4. **Serialization**: Convert $\mathbf{W}$ to little-endian byte sequence
5. **Counter Increment**: Increment block counter for subsequent operations

The final keystream block is computed as:

$$
Keystream = Serialize(S_{initial} + W_{20})
$$

$W_{20}$ represents the working state after 20 transformation rounds.

## API Specification and Usage

### Context Management Operations

The implementation provides structured context management for maintaining cipher state:

```c
#include "src/chacha20.h"

// Context instantiation
chacha20_ctx *ctx = chacha20_new();

// Context deallocation
chacha20_free(ctx);
```

### Initialization Procedures

Context initialization requires specification of cryptographic parameters:

```c
uint8_t key[CHACHA20_KEY_SIZE] = { /* 256-bit key material */ };
uint8_t nonce[CHACHA20_NONCE_SIZE] = { /* 96-bit nonce */ };
uint32_t counter = 0; // Initial block counter value

chacha20_init(ctx, key, nonce, counter);
```

### Cryptographic Operations

The implementation provides symmetric encryption and decryption operations using bitwise XOR between data and keystream:

$$C_i = P_i \oplus K_i \quad \text{(Encryption)}$$
$$P_i = C_i \oplus K_i \quad \text{(Decryption)}$$

```c
const uint8_t *plaintext = /* input data buffer */;
uint8_t *ciphertext = /* output data buffer */;
size_t length = /* data length in bytes */;

// Encryption operation
chacha20_encrypt(ctx, plaintext, ciphertext, length);

// Decryption operation (functionally identical due to XOR properties)
chacha20_decrypt(ctx, ciphertext, plaintext, length);
```

### Counter Management Functions

For stream positioning and operational control:

```c
// Counter reset operation
chacha20_reset_counter(ctx, new_counter_value);
```

**Important Security Notes:**

- Counter values must maintain uniqueness for identical key-nonce pairs
- Maximum data volume per key-nonce pair: $(2^{32}-1) \times 64$ bytes ≈ 247.88 GB
- Counter reset operations are primarily for stream positioning
- Alternative nonce selection is preferred over counter reuse

## Example Usage

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

## Nonce Uniqueness and Counter Management

The security of ChaCha20 fundamentally depends on nonce uniqueness. For a given key $K$:

$$\forall i \neq j: N_i \neq N_j$$

**Operational Constraints:**

- Maximum of $2^{32}-1$ blocks per key-nonce pair (≈ 247.88 GB)
- Counter overflow prevention through proactive key rotation
- Maintenance of counter monotonicity for stream positioning
- Implementation of counter overflow detection mechanisms

## Side-Channel Mitigation

**Constant-Time Operations:**
The quarter round operations maintain constant execution time:
$$T_{QR} \text{ is independent of secret input values}$$

- Data-independent execution patterns
- Avoidance of secret-dependent conditional branches
- Cache-timing attack resistance through algorithmic design

### Performance Analysis

The encryption demonstrates linear time complexity and predictable performance:

$$T_{\text{encrypt}}(n) \approx \lceil \frac{n}{64} \rceil \times T_{\text{block}} + T_{\text{setup}}$$

**Key Advantages:**

- Superior software performance compared to AES without hardware acceleration
- Minimal computational overhead and memory footprint
- Parallel processing compatibility and scalability
- Inherent resistance to differential and linear cryptanalytic attacks

## Applications and Use Cases

ChaCha20 demonstrates superior characteristics for various deployment scenarios:

- **Network Communication**: High-performance TLS alternative without hardware acceleration requirements
- **File System Encryption**: Memory-efficient processing for large-scale file operations
- **Embedded Systems**: Minimal computational overhead and reduced memory footprint
- **High-Performance Computing**: Superior software performance and parallel processing compatibility

## Future Development and Extensions

## References and Standards

- [RFC 7539: ChaCha20 and Poly1305 for IETF Protocols](https://tools.ietf.org/rfc/rfc7539.txt) - Official Internet Engineering Task Force specification
- [RFC 7905: ChaCha20 and Poly1305 based Cipher Suites for TLS](https://tools.ietf.org/rfc/rfc7905.txt) - Transport Layer Security integration specification

- [Daniel J. Bernstein's ChaCha20 specification](https://cr.yp.to/chacha.html) - Original algorithm specification and analysis
- [Original ChaCha paper](https://cr.yp.to/chacha/chacha-20080128.pdf) - Foundational cryptographic research publication

## TODO

- [ ] ChaCha20-Poly1305 AEAD Support - Add authenticated encryption mode
- [ ] Key Derivation Function - Integrate PBKDF2/Argon2 support for secure key generation
