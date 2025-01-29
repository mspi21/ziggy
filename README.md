# Ziggy 🐶

> [!CAUTION]
> Do not use this library! It is an educational/experimental project not intended for production use.

Ziggy is an experimental cryptographic library. The (continuous) goal of the project is to:

- Implement modern cryptographic algorithms/protocols,
- test the implementations for known attacks and thus learn which aspects of the algorithms are prone to mistakes,
- experiment with API design choices and how they may affect safe usage of the library,
- learn the Zig language and the way it interoperates with C and other languages (C++, Rust, Python).

## Capabilities

Ziggy implements all cryptographic primitives from scratch. These cryptographic primitives are in themselves unsafe,
as they typically require usage that is not entirely straightforward. However, ziggy still chooses to expose them to
advanced (theoretical) users.

Most (**theoretical!**) users should directly use one of the cryptographic *protocols*.

### Primitives

- Advanced Encryption Standard (FIPS 197): AES-128, AES-192, AES-256
- ChaCha20 (RFC 7539): ChaCha20 with 64-bit nonce and 64-bit counter, ChaCha20 with 96-bit nonce and 32-bit counter
- Salsa20: Salsa20/20 with 256-key, Salsa20/20 with 128-bit key
- Secure Hashing Algorithm: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256

### Protocols

## Roadmap

### Code quality

- Use std library functions where possible
- Refactor data manipulation (LE/BE int serialization, word rotations, etc.) into one place
- Use @TypeInfo, @divExact, etc. to correctly abstract int sizes

### Primitives

- DES, 3DES
- Block cipher modes: CBC-PKCS7, CFB, OFB, CTR, GCM
- Poly1305
- HMAC
- BigIntegers & modular arithmetic
- Cryptographically secure random BigInteger generation & primality testing
- Elliptic Curve groups (over Fp fields)
- ASN.1 (de)serialization from/into DER/PEM
- Optimal Assymetric Encryption Padding (OAEP)

### Protocols

- Authenticated Encryption with Additional Data (AEAD): AES-GCM, ChaCha20-Poly1305
- Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)
- Elliptic Curve Diffie-Hellmann Key Exchange (ECDH)

