# XYO Cryptography — Documentation

`xyo-cryptography` is the hashing, encryption and random number layer of the
XYO C++ library stack. It sits on top of `xyo-system` and gives the XYO tools
(`file-crypt`, `fabricare`, the `quantum-script` extensions `sha256`,
`sha512`, `md5`, `crypt`, `random`, ...) **small, dependency free
implementations** of the primitives they need:

- **Hash functions.** `MD5`, `SHA256` and `SHA512`, each with a one call
  form (`SHA256::hash(text)` gives lowercase hex) and a streaming form
  (`processInit` / `processU8` / `processDone`) for data that arrives in
  pieces. The hash state can be copied, so a common prefix is hashed once.
- **File hashing.** `Util::fileHashSHA256` / `fileHashSHA512` hash a file of
  any size in 32 KB blocks and fail cleanly on read errors.
- **Authenticated encryption.** `Crypt::encrypt` / `decrypt` (and the
  `...File` variants) protect a buffer with a 64 byte key, normally the
  SHA512 of a password. The output carries a random seed and a SHA512
  signature, so a wrong key, a modified byte or a truncated file is
  rejected before any plaintext is returned.
- **Random numbers.** `SystemRandom::generate` reads the operating system
  generator (`BCryptGenRandom` on Windows, `getrandom` / `/dev/urandom` on
  Linux) for keys and salts. `RandomMT` is a fast, reproducible Mersenne
  Twister (MT19937) for simulations, tests and games — **not** for secrets.
- **Byte transforms.** `xor8` (XOR a buffer with a key) and `Avalanche`
  (a reversible running XOR that spreads every byte into the following
  ones), building blocks used by the tools above.

```
quantum-script extensions, file-crypt, fabricare, applications ...
xyo-cryptography      <-- this library
xyo-system            (File, Buffer, Shell::fileGetContents, DateTime)
xyo-encoding          (String, UConvert, THex, Base64)
xyo-multithreading    (Thread, Worker)
xyo-data-structures   (containers, IRead / IWrite)
xyo-managed-memory    (Object, TPointer, per-thread pools)
xyo-platform          (macros, TAtomic, CriticalSection)
```

## Why it exists

The XYO tools need to check downloads against a published SHA512, store
build fingerprints, encrypt a file with a password, or pick a random number
in a script. Pulling OpenSSL into every one of them for that would add a
large build dependency and a second memory and string model. This library
keeps those needs inside the XYO stack: the types are `String` and `Buffer`,
the code is plain C++17, the same on Windows and Linux, and it builds with
fabricare like every other XYO library.

## What it is not

Read this before choosing it for new work:

- **`Crypt` is a custom construction**, not a standard scheme such as
  AES-GCM or ChaCha20-Poly1305. It is built only from SHA512 (SHA512 in
  counter mode as the key stream, a keyed SHA512 as the signature). It is
  tested for round trips and tamper rejection, but it has not been
  reviewed by third parties and its file format is understood only by this
  library. Use it for XYO tools and data that stays within XYO programs.
  When you need interoperability, compliance or a reviewed design, use
  OpenSSL (`vendor-openssl`, the `quantum-script--openssl` extension).
- **There is no password stretching.** The key is `SHA512(password)`, one
  hash. A weak password can be guessed quickly by anyone who has the
  encrypted file. Use long passphrases or a random 64 byte key file
  (see [Crypt](crypt.md#keys)).
- **MD5 is broken** for anything an attacker controls (collisions are
  cheap). Keep it for checksums and compatibility with existing data.
- **`RandomMT` is predictable.** 624 outputs reveal its whole state. Use
  `SystemRandom` for keys, salts, tokens and anything secret.
- **`xor8` and `Avalanche` are not encryption** on their own.
- **No HMAC, no KDF, no public key cryptography, no constant time
  comparison.** Hash outputs are compared with `==` / `memcmp`.

## Concepts at a glance

| Need | Use | Notes |
|------|-----|-------|
| Hash of a string, as hex | `SHA256::hash(s)`, `SHA512::hash(s)`, `MD5::hash(s)` | lowercase hex; uses `s.length()`, binary safe |
| Hash of a string, as bytes | `SHA512::hashToU8(s, out)` | `out` is 16 / 32 / 64 bytes for MD5 / SHA256 / SHA512 |
| Hash data given in pieces | `SHA256 h; h.processU8(p, n); ... h.processDone(); h.getHashHex()` | or `h.toU8(out)` |
| Hash many messages with the same prefix | hash the prefix once, then `copy()` the state per message | |
| Hash a file | `Util::fileHashSHA256(name, hex)`, `Util::fileHashSHA512(name, hex)` | `false` if the file cannot be read completely |
| Encrypt a buffer with a password | `SHA512::hashToU8(password, key)` then `Crypt::encrypt(key, 64, data, n, out)` | output is `136 + (n / 64 + 1) * 64` bytes |
| Decrypt and verify | `Crypt::decrypt(key, 64, data, n, out)` | `false` on wrong key or any change |
| Encrypt / decrypt a file | `Crypt::encryptFile`, `Crypt::decryptFile` | whole file in memory |
| Check an encrypted file is a known version | `Crypt::checkIntegrity(key, 64, data, n, signature)` | `signature` = bytes 64..127 of the encrypted data |
| Secure random bytes | `SystemRandom::generate(buffer, n)` | `false` if the OS generator fails |
| Reproducible pseudo random numbers | `RandomMT r; r.seed(s); r.nextRandom()` | same sequence as `std::mt19937(s)` |
| XOR with a key | `xor8(data, n, key, keyLn)` | only `min(n, keyLn)` bytes, the key is **not** repeated |
| Spread bytes forward, reversibly | `Avalanche::encode` / `decode` | in place |

## Contents

| Document | What it covers |
|----------|----------------|
| [Getting started](getting-started.md) | Build it, depend on it (DLL or static), first program, threads, building without fabricare |
| [Hashing](hashing.md) | `MD5`, `SHA256`, `SHA512`: one call, streaming, bytes vs hex, state copy, file hashing, pitfalls |
| [Crypt](crypt.md) | Encrypting buffers and files, keys, the file format, integrity checks, security notes |
| [Random numbers](random.md) | `SystemRandom` and `RandomMT`, choosing between them, seeding, ranges |
| [Byte transforms](transforms.md) | `xor8`, `Avalanche` |
| [API reference](reference.md) | Every public symbol on one page |

`String`, `Buffer`, `File` and `Shell::` come from the layers below; see
`docs/` in the `xyo-encoding` and `xyo-system` repositories.

## Source map

```
source/XYO/Cryptography.hpp                 umbrella header, include this
source/XYO/Cryptography.Amalgam.cpp         the whole library in one translation unit
source/XYO/Cryptography/
    Dependency.hpp                          xyo-system, export macros, namespace imports
    MD5[.cpp]                               MD5 (RFC 1321)
    SHA256[.cpp]                            SHA-256 (FIPS 180-4)
    SHA512[.cpp]                            SHA-512 (FIPS 180-4)
    Util[.cpp]                              fileHashSHA256, fileHashSHA512
    Crypt[.cpp]                             encrypt / decrypt / encryptFile / decryptFile / checkIntegrity
    SystemRandom.hpp                        operating system random bytes
    SystemRandom-OS-Windows.cpp             BCryptGenRandom, loaded at run time
    SystemRandom-OS-Linux.cpp               getrandom syscall, /dev/urandom fallback
    RandomMT[.cpp]                          Mersenne Twister MT19937
    XOR8[.cpp]                              xor8
    Avalanche[.cpp]                         Avalanche::encode / decode
    Copyright / License / Version           library metadata
test/test.01.cpp                            SHA256 known answers
test/test.02.cpp                            SHA512 known answers
test/test.03.cpp                            MD5 known answers
test/test.04.cpp                            Crypt round trip and checkIntegrity
test/test.05.cpp                            streaming: any split gives the same hash
test/test.06.cpp                            Crypt: all sizes 0..200, wrong key, bit flips, forged length, truncation
test/test.07.cpp                            Util file hashes around the 32 KB read block
test/test.08.cpp                            SystemRandom, Crypt seeds differ for identical input
```

## AI assistant skill

A Claude Code skill describing how to use this library lives in
[`.claude/skills/xyo-cryptography/`](../.claude/skills/xyo-cryptography/SKILL.md).
It is picked up automatically inside this repository; copy the folder to
`~/.claude/skills/` to have it available in the projects that depend on
`xyo-cryptography`.
