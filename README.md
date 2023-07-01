# SafeLock - Django based secret manager
My first Python project related to cryptography.

## Cryptography

### Python cryptography libraries
- [cryptography](https://cryptography.io/en/latest/)

### Key derivation function
- PBKDF2
- Iterations: 100 000
- Salt: 128 bits
- Key length: 256 bits

### Symetric encryption
- Algorithm: AES-256
- Key length: 256 bits
- Mode: GCM (Galois/Counter Mode)
- Block size: 128 bits
- Authentication tag: 112 bits
- Initialization vector (IV): 96 bits, random, different for every record

### Hashing
- SHA-256