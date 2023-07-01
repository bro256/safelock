# SafeLock - Django based secret manager
My first Python project related to cryptography.

## Cryptography

### Python cryptography libraries
- [cryptography](https://cryptography.io/en/latest/)

### Key derivation function
PBKDF2
- Iterations: 600 000
- Salt: 128 bits
- Key length: 32 bytes (256 bits)

### Symetric encryption
- Algorithm: AES-256
- Key length: 256 bits
- Mode: CBC
- Initialization vector (IV): random 256 bits, different for every record
- Padding: PKCS7

### Hashing
- SHA-256