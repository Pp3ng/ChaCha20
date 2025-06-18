# ChaCha20-Poly1305 AEAD Implementation in C

This project provides a complete C implementation of the ChaCha20 stream cipher and Poly1305 message authentication code (MAC), along with their combined authenticated encryption with associated data (AEAD) mode. It includes a command-line tool for file encryption and a comprehensive test suite to ensure compliance with RFC 7539.

## Core Components

- **ChaCha20 Stream Cipher** - RFC 7539 compliant encryption
- **Poly1305 MAC** - RFC 7539 compliant authentication
- **ChaCha20-Poly1305 AEAD** - Combined authenticated encryption
- **Vault File Encryption Tool** - Command-line utility with ChaCha20-Poly1305
- **Comprehensive Test Suite** - RFC compliance and robustness validation

## Project Structure

```
├── src/                    # Core library
│   ├── chacha20.h/c       # ChaCha20 implementation
│   ├── poly1305.h/c       # Poly1305 implementation
│   ├── aead.h/c           # ChaCha20-Poly1305 AEAD
│   └── common.h/c         # Common utilities
├── test/                  # Test suite
│   ├── test_chacha20.c    # ChaCha20 tests
│   ├── test_poly1305.c    # Poly1305 tests
│   └── test_aead.c        # AEAD tests
├── vault.c               # File encryption tool
└── Makefile
```

## Building and Running

```bash
# Build all components
make all

# Run tests
make test

# Build vault tool
make vault

# Clean build
make clean
```

---

## Vault File Encryption Tool

Command-line AEAD file encryption with ChaCha20-Poly1305:

```bash
# Seal file (auto-generate key)
./vault -s input.txt output.enc

# Seal with specified key
./vault -s input.txt output.enc a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789a

# Open file
./vault -o output.enc decrypted.txt a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789a
```

### Encrypted File Format

The vault tool produces encrypted files with the following binary structure:

```bash
[nonce (12 bytes)][ciphertext (variable length)][tag (16 bytes)]
```

**Security Properties:**

- Each file uses a unique random nonce (no nonce reuse)
- Authentication tag covers both the ciphertext and any associated data
- Constant-time tag verification prevents timing attacks
- Files are authenticated before decryption (fail-fast on tampering)

**Streaming Processing:** Files are processed in 8KB chunks for memory efficiency

---

## API Usage

### ChaCha20 Stream Cipher

```c
#include "src/chacha20.h"

// CHACHA20_KEY_SIZE = 32 bytes (256-bit key)
// CHACHA20_NONCE_SIZE = 12 bytes (96-bit nonce)

// Key and nonce generation
uint8_t key[CHACHA20_KEY_SIZE], nonce[CHACHA20_NONCE_SIZE];
chacha20_keygen(key);         // Generate random key
chacha20_noncegen(nonce);     // Generate random nonce

// Initialize
chacha20_ctx *ctx = chacha20_new();
chacha20_init(ctx, key, nonce, 0);

// Encrypt/Decrypt (symmetric operation)
uint8_t plaintext[] = "Hello, World!";
uint8_t ciphertext[sizeof(plaintext)];
chacha20_encrypt(ctx, plaintext, ciphertext, sizeof(plaintext));

// Safe reinitialization with new parameters
uint8_t new_key[CHACHA20_KEY_SIZE], new_nonce[CHACHA20_NONCE_SIZE];
chacha20_keygen(new_key);
chacha20_noncegen(new_nonce);
chacha20_reinit(ctx, new_key, new_nonce, 0);  // Safely reinitialize

// Process more data with new parameters
uint8_t plaintext2[] = "Another message";
uint8_t ciphertext2[sizeof(plaintext2)];
chacha20_encrypt(ctx, plaintext2, ciphertext2, sizeof(plaintext2));

// Cleanup
chacha20_clear(ctx);
chacha20_free(ctx);
```

### Poly1305 MAC

```c
#include "src/poly1305.h"

// POLY1305_KEY_SIZE = 32 bytes (256-bit key)
// POLY1305_TAG_SIZE = 16 bytes (128-bit authentication tag)

// One-shot authentication
uint8_t key[POLY1305_KEY_SIZE], tag[POLY1305_TAG_SIZE];
uint8_t data[] = "Message to authenticate";
chacha20_keygen(key);  // Generate secure key
poly1305_auth(key, data, sizeof(data), tag);

// Streaming authentication
poly1305_ctx *ctx = poly1305_new();
poly1305_init(ctx, key);
poly1305_update(ctx, data, sizeof(data));
poly1305_finalize(ctx, tag);

// Verify tag
uint8_t received_tag[POLY1305_TAG_SIZE];
// ... receive tag from somewhere ...
bool valid = poly1305_verify(tag, received_tag);

// Cleanup
poly1305_clear(ctx);
poly1305_free(ctx);
```

### ChaCha20-Poly1305 AEAD

```c
#include "src/aead.h"

// AEAD_KEY_SIZE = 32 bytes (256-bit key)
// AEAD_NONCE_SIZE = 12 bytes (96-bit nonce)
// AEAD_TAG_SIZE = 16 bytes (128-bit authentication tag)
// AEAD_MAX_DATA_SIZE = 274 GB per (key, nonce) pair
// AEAD_MAX_AAD_SIZE = ~2.3 EB associated data limit

// One-shot API
uint8_t key[AEAD_KEY_SIZE], nonce[AEAD_NONCE_SIZE];
uint8_t plaintext[] = "Secret message";
uint8_t aad[] = "Associated data";

// Generate key and nonce
chacha20_keygen(key);
chacha20_noncegen(nonce);

// Seal (encrypt + authenticate)
uint8_t sealed[sizeof(plaintext) + AEAD_TAG_SIZE];
bool success = aead_seal(key, nonce,
                        aad, sizeof(aad),
                        plaintext, sizeof(plaintext),
                        sealed);

// Open (decrypt + verify)
uint8_t decrypted[sizeof(plaintext)];
success = aead_open(key, nonce,
                   aad, sizeof(aad),
                   sealed, sizeof(sealed),
                   decrypted);
```

### Streaming AEAD

```c
// Streaming seal (encryption + authentication)
aead_stream_ctx *stream = aead_stream_new();
aead_stream_seal_init(stream, key, nonce, aad, aad_len);

// Process data in chunks
while (has_data) {
    aead_stream_seal_update(stream, chunk, chunk_size, ciphertext_chunk);
}

uint8_t tag[AEAD_TAG_SIZE];
aead_stream_seal_final(stream, tag);
aead_stream_free(stream);

// Streaming open (decryption + verification)
aead_stream_ctx *stream2 = aead_stream_new();
aead_stream_open_init(stream2, key, nonce, aad, aad_len);

// Process ciphertext chunks
while (has_ciphertext_data) {
    aead_stream_open_update(stream2, ciphertext_chunk, chunk_size, plaintext_chunk);
}

// Verify authentication tag
bool authentic = aead_stream_open_final(stream2, tag);
if (!authentic) {
    // Authentication failed - data corrupted or wrong key
}

aead_stream_clear(stream2);
aead_stream_free(stream2);
```

---

# Mathematical Foundations of ChaCha20 Poly1305 AEAD

Mathematical analysis of the ChaCha20 stream cipher, Poly1305 MAC, and their AEAD construction.

## ChaCha20 Stream Cipher

### State Matrix

ChaCha20 operates on a 4×4 state matrix $\mathbf{S} \in (\mathbb{Z}_{2^{32}})^{4 \times 4}$:

$$
\mathbf{S}_{\text{initial}} = \begin{bmatrix}
\sigma_0 & \sigma_1 & \sigma_2 & \sigma_3 \\
k_0 & k_1 & k_2 & k_3 \\
k_4 & k_5 & k_6 & k_7 \\
\text{counter} & n_0 & n_1 & n_2
\end{bmatrix}
$$

Where:

- **Constants**: $\sigma_i$ = ASCII of "expand 32-byte k" (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)
- **Key**: $K = (k_0, \ldots, k_7)$ where $K \in \{0,1\}^{256}$
- **Nonce**: $N = (n_0, n_1, n_2)$ where $N \in \{0,1\}^{96}$
- **Counter**: $\text{counter} \in \mathbb{Z}_{2^{32}}$

### Operations

- **Modular Addition**: $a \boxplus b = (a + b) \bmod 2^{32}$
- **XOR**: $a \oplus b$
- **Left Rotation**: $a \lll n = (a \ll n) \lor (a \gg (32-n))$

### Quarter Round Function

The core operation $QR: (\mathbb{Z}_{2^{32}})^4 \to (\mathbb{Z}_{2^{32}})^4$:

$$
\begin{align}
a' &= a \boxplus b, \quad d' = (d \oplus a') \lll 16 \\
c' &= c \boxplus d', \quad b' = (b \oplus c') \lll 12 \\
a'' &= a' \boxplus b', \quad d'' = (d' \oplus a'') \lll 8 \\
c'' &= c' \boxplus d'', \quad b'' = (b' \oplus c'') \lll 7
\end{align}
$$

Output: $(a'', b'', c'', d'')$. Each quarter round is bijective with non-linear properties.

### Block Transformation

ChaCha20 applies 20 rounds (10 double rounds) of transformations:

**Column Rounds** (columns):

$$
\begin{align}
QR(S_0, S_4, S_8, S_{12}), \quad QR(S_1, S_5, S_9, S_{13}) \\
QR(S_2, S_6, S_{10}, S_{14}), \quad QR(S_3, S_7, S_{11}, S_{15})
\end{align}
$$

**Diagonal Rounds** (diagonals):

$$
\begin{align}
QR(S_0, S_5, S_{10}, S_{15}), \quad QR(S_1, S_6, S_{11}, S_{12}) \\
QR(S_2, S_7, S_8, S_{13}), \quad QR(S_3, S_4, S_9, S_{14})
\end{align}
$$

**Keystream Generation**:

$$
\text{Keystream}_i = \text{Serialize}(T^{20}(\mathbf{S}_{\text{initial}}) \boxplus \mathbf{S}_{\text{initial}})
$$

**Encryption**: $E_K^N(M) = M \oplus \bigoplus_{i=0}^{\lceil |M|/64 \rceil - 1} \text{ChaCha20Block}(K, N, i)$

**Counter Limit**: Maximum $2^{32} - 1$ blocks per $(K,N)$ pair $(≈274.88GB)$.

## Poly1305 MAC

### Prime Field

Poly1305 operates over $\mathbb{F}_p$ where:

$$
p = 2^{130} - 5 = 1361129467683753853853498429727072845819
$$

Elements represented in radix-$2^{26}$ with 5 limbs:

$$
x = \sum_{i=0}^{4} x_i \cdot 2^{26i}
$$

### Polynomial Hash

Authentication tag computation:

$$
\text{Tag} = \left( \left(\sum_{i=0}^{n-1} m_i \cdot r^{n-1-i}\right) \bmod p + s \right) \bmod 2^{128}
$$

Where:

- $r \in \mathbb{F}_p$: Clamped evaluation point from key
- $s \in \mathbb{Z}_{2^{128}}$: Additive offset
- $m_i \in \mathbb{F}_p$: Message blocks with padding
- $n$: Number of blocks

### Key Derivation

256-bit key $K$ is split as $K = r \| s$ where:

$$
r = K[0:16] \land \text{0x0ffffffc0ffffffc0ffffffc0fffffff}
$$

$$
s = K[16:32]
$$

**Clamping**: Clears specific bits to ensure $r \equiv 0 \pmod{4}$ and $r < 2^{124}$, resulting in $\approx 2^{106}$ bits entropy.

### Message Processing

Each 16-byte block $M_i$ becomes:

$$
m_i = \text{LE}_{128}(M_i) + 2^{128}
$$

Incomplete final block of length $\ell < 16$:

$$
m_{\text{final}} = \text{LE}_{\ell \times 8}(M_{\text{final}}) + 2^{\ell \times 8}
$$

### Field Arithmetic

**Modular Reduction**: $x \bmod p = (x \bmod 2^{130}) + 5 \times \lfloor x / 2^{130} \rfloor$

**Horner's Method**: $h_0 = 0$, $h_{i+1} = ((h_i + m_i) \cdot r) \bmod p$

### Security Properties

**Universal Hash**: For $M_1 \neq M_2$:

$$
\Pr_{r \leftarrow \mathbb{F}_p}[H_r(M_1) = H_r(M_2)] \leq \frac{\max(|M_1|, |M_2|)}{16 \cdot p}
$$

**Forgery Resistance**:

$$
\text{Adv}^{\text{forge}}_{\text{Poly1305}}(A) \leq \frac{q \cdot \ell_{\max}}{16 \cdot p} + \frac{1}{2^{128}}
$$

## ChaCha20-Poly1305 AEAD

### Construction

**Inputs**:

- $K \in \{0,1\}^{256}$: Master key
- $N \in \{0,1\}^{96}$: Nonce
- $A \in \{0,1\}^*$: Associated data
- $M \in \{0,1\}^*$: Plaintext

**Poly1305 Key Derivation**:

$$
\text{PolyKey} = r \| s = \text{ChaCha20Block}(K, N, 0)[0:32]
$$

**Encryption**:

$$
C = M \oplus \bigoplus_{i=1}^{\lceil |M|/64 \rceil} \text{ChaCha20Block}(K, N, i)
$$

**MAC Input Construction**:

$$
\text{MAC\_Input} = \text{Pad}_{16}(A) \| \text{Pad}_{16}(C) \| \text{LE}_{64}(|A|) \| \text{LE}_{64}(|C|)
$$

**Authentication Tag**:

$$
\text{Tag} = \text{Poly1305}(r \| s, \text{MAC\_Input})
$$

**Output**: $(C, \text{Tag})$

### Decryption

1. Derive authentication key: $r \| s = \text{ChaCha20Block}(K, N, 0)[0:32]$
2. Recompute tag: $\text{Tag}' = \text{Poly1305}(r \| s, \text{MAC\_Input})$
3. Verify in constant time: if $\text{Tag} = \text{Tag}'$, decrypt; else return $\perp$
4. Decrypt: $M = C \oplus \text{KeyStream}[0:|C|]$

## Security Analysis

### ChaCha20 Security

**Differential Cryptanalysis**: Probability of non-trivial differential over $r$ rounds:

$$
\text{DP}^r \leq \left(\frac{1}{2^n}\right)^{\text{active rounds}}
$$

**Linear Cryptanalysis**: For 20 rounds:

$$
\text{LP}^{20} \leq 2^{-\text{security margin}}
$$

where security margin > 128 bits.

### Poly1305 Security

**ε-Almost Universal**: For distinct messages $M_1 \neq M_2$ with $\ell$ blocks maximum:

$$
\Pr_{r}[H_r(M_1) = H_r(M_2)] \leq \varepsilon = \frac{\ell}{p}
$$

**Unforgeability**:

$$
\text{Adv}^{\text{UF-CMA}}_{\text{Poly1305}}(t, q, \ell) \leq \frac{q \cdot \ell}{p} + \frac{1}{2^{128}}
$$

### AEAD Security

**IND-CCA2**:

$$
\text{Adv}^{\text{IND-CCA2}}_{\text{ChaCha20-Poly1305}}(A) \leq \varepsilon_{\text{ChaCha20}} + \varepsilon_{\text{Poly1305}}
$$

**INT-CTXT**:

$$
\text{Adv}^{\text{INT-CTXT}}_{\text{ChaCha20-Poly1305}}(A) \leq \frac{q \cdot \ell_{\max}}{2^{130}-5} + \frac{1}{2^{128}}
$$

---

## References

- [RFC 7539: ChaCha20 and Poly1305 for IETF Protocols](https://tools.ietf.org/rfc/rfc7539.txt)
- [Daniel J. Bernstein's ChaCha20 specification](https://cr.yp.to/chacha.html)
- [Original ChaCha paper](https://cr.yp.to/chacha/chacha-20080128.pdf)

## TODO

- [x] ChaCha20-Poly1305 AEAD Support - Add authenticated encryption mode
- [ ] Key Derivation Function - Integrate PBKDF2/Argon2 support for secure key generation
