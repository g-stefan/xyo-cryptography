---
name: xyo-cryptography
description: >-
  How to use the xyo-cryptography C++ library (namespace XYO::Cryptography),
  the hashing, encryption and random layer of the XYO C++ stack on top of
  xyo-system: the hash classes MD5 / SHA256 / SHA512 (hash, hashToU8,
  processInit / processU8 / processDone, getHashHex, toU8, copy),
  Util::fileHashSHA256 / fileHashSHA512, the authenticated file and buffer
  encryption Crypt::encrypt / decrypt / encryptFile / decryptFile /
  checkIntegrity (64 byte SHA512 key, seed + signature format),
  SystemRandom::generate (BCryptGenRandom / getrandom), the Mersenne Twister
  RandomMT (seed, nextRandom, getValue), xor8 and Avalanche::encode /
  decode. Use when writing or reviewing code that includes
  <XYO/Cryptography.hpp>, depends on "xyo-cryptography" in fabricare.json,
  hashes, encrypts or generates random data in XYO code, uses any of these
  names, or when working inside the xyo-cryptography repository or programs
  built on it (file-crypt, fabricare, quantum-script extensions md5 /
  sha256 / sha512 / crypt / random).
---

# xyo-cryptography

Hashing, encryption and random numbers for the XYO C++ libraries, on top of
`xyo-system` (see the `xyo-system`, `xyo-encoding` and `xyo-managed-memory`
skills; their rules apply: `String`, `Buffer`, one thread per object).
Purpose: **small, dependency free primitives for XYO tools** (download
checks, build fingerprints, password protected files, script random
numbers) without OpenSSL.

Full documentation: `docs/` in the xyo-cryptography repository
(`X:\Storage\XYO\Gitea\CPP\xyo-cryptography\docs` on this machine): README
(purpose, limits), getting-started, **hashing**, **crypt** (keys, format,
security), random, transforms, reference. Read the matching page when you
need more than this summary. When in doubt read the header in
`source/XYO/Cryptography/`.

## Pick the right tool

| Need | Use | Not |
|------|-----|-----|
| fingerprint / checksum | `SHA256`, `SHA512` | `MD5` (broken; legacy data only) |
| hash a file | `Util::fileHashSHA256/512(name, hex)` | reading the whole file into a `String` |
| encrypt data for XYO tools | `Crypt` with a 64 byte key | `xor8` / `Avalanche` alone |
| interoperable / reviewed crypto (AES-GCM, TLS, public key) | OpenSSL (`vendor-openssl`) | `Crypt` (custom format, not externally reviewed) |
| keys, salts, tokens | `SystemRandom::generate` | `RandomMT`, `rand()` |
| reproducible random (tests, games, simulations) | `RandomMT` with a fixed seed | `SystemRandom` |
| message authentication | HMAC built on the streaming API (docs/hashing.md recipe) | `SHA256(key || msg)` (length extension) |
| storing user passwords | a real password hash (Argon2 / scrypt / PBKDF2) | any single SHA hash |

## Hashes: MD5 / SHA256 / SHA512

Digest 16 / 32 / 64 bytes, hex 32 / 64 / 128 chars, **lowercase**.

```cpp
String hex = SHA256::hash(s);                // hashes s.length() bytes, binary safe
uint8_t d[64]; SHA512::hashToU8(s, d);       // raw digest

SHA512 h;                                    // constructor calls processInit()
h.processU8(p, n); h.processU8(q, m);        // any split, same result
h.processDone();                             // ONCE
h.getHashHex(); h.toU8(d);                   // read as often as needed
h.processInit();                             // to reuse the object
other.copy(h);                               // copy state (mid-message too)
```

Rules:

1. `processU8` takes `const uint8_t *`: cast text with
   `reinterpret_cast<const uint8_t *>(s.value())`, pass `s.length()`.
2. **`processDone()` exactly once**; more `processU8` or a second
   `processDone` after it silently gives a wrong digest. Reset with
   `processInit()`.
3. Classes are `XYO_PLATFORM_DISALLOW_COPY_ASSIGN_MOVE`: no `=`, use
   `copy()`. Live fine on the stack. Not thread safe per object.
4. Do not call `hashBlock()` (internal).
5. `hash("literal")` goes through `String(const char *)` and stops at the
   first `0`; use `String(ptr, len)` for binary data.
6. Compare with `==` on lowercase hex (`toLowerCaseASCII()` foreign hex)
   or `memcmp` on bytes. Hex <-> bytes: `Buffer::toHex()` / `fromHex()`,
   `Base16::decode`.

## Util

`Util::fileHashSHA256(const char *, String &hex)` /
`fileHashSHA512(...)`: 32 KB blocks; `false` if the file cannot be opened
or was not read completely (size check); `hex` assigned only on success. No
MD5 variant: stream with `File` (docs/hashing.md).

## Crypt

```cpp
uint8_t key[64];
SHA512::hashToU8(passwordText, key);         // the XYO convention, file-crypt does the same
Buffer enc;
Crypt::encrypt(key, 64, data, dataSize, enc);              // cannot fail
Buffer dec;
if (!Crypt::decrypt(key, 64, enc.buffer, enc.length, dec)) { /* wrong key / damaged */ };
Crypt::encryptFile(key, 64, "in", "out");                  // bool, whole file in memory
Crypt::decryptFile(key, 64, "in", "out");                  // writes out only on success
Crypt::checkIntegrity(key, 64, enc.buffer, enc.length, signature64);
```

Rules:

1. **The `password` parameter is key bytes, not the typed password.**
   Crypt does not hash it. Encrypt and decrypt must derive the key the same
   way (normally `SHA512::hashToU8(password, key)`, 64 bytes; or 64 bytes
   from `SystemRandom` stored in a key file).
2. Output size `136 + (n / 64 + 1) * 64`. Layout: `[seed 64][signature
   64][length 8, encrypted][data, m*64, encrypted]`. Signature = bytes
   64..127.
3. `decrypt` verifies the signature before decrypting; `output` is written
   only on success. Rejects wrong key, any bit flip, forged length,
   truncation, input < 136 bytes.
4. Same input encrypted twice differs (seed = SHA512(key, data, time,
   SystemRandom)).
5. Input and output must be different `Buffer`s. No streaming API.
6. `checkIntegrity(..., integrity)`: `true` only if the signature verifies
   **and** equals `integrity` (a saved signature, "same file as before");
   pass `&enc.buffer[64]` to only check intactness.
7. Security: custom SHA512 counter mode + keyed SHA512, not a standard
   AEAD; key from a password is one SHA512 (no salt, no stretching);
   `memcmp` not constant time. Say so when someone asks if it is "secure";
   suggest OpenSSL for interop / compliance.

## Random

```cpp
uint8_t buf[32];
if (!SystemRandom::generate(buf, sizeof(buf))) { /* fail closed */ };

RandomMT r;              // seeded with time(nullptr)
r.seed(12345);           // reproducible; equals std::mt19937(12345)
uint32_t v = r.nextRandom();
r.getValue();            // last value, does not advance
```

- `SystemRandom`: Windows `BCryptGenRandom` (bcrypt.dll loaded at run time,
  no link lib), Linux `getrandom` syscall then `/dev/urandom`. `false` if no
  source works -> do not fall back to a weak value. Thread safe.
- `RandomMT`: **`seed(0)` = seed from the clock**, not seed zero. Predictable
  after 624 outputs; never for secrets. One object per thread. `copy()` to
  clone. Range without bias: rejection sampling (docs/random.md).

## xor8 / Avalanche

- `xor8(inOut, inOutLn, key, keyLn)` XORs only `min(inOutLn, keyLn)` bytes:
  **the key is not repeated**. Self inverse.
- `Avalanche::encode(data, n)`: in place running XOR (`data[i+1] ^=
  data[i]`), `decode` reverses. No key; not encryption.

## Using it

- `#include <XYO/Cryptography.hpp>` (umbrella). C++17. `using namespace
  XYO::Cryptography;` also brings `String`, `Buffer`, `File`, `Shell`,
  `UConvert`. Qualify `XYO::Cryptography::Version::version()` (every XYO
  library has `Version`, `Copyright`, `License`).
- fabricare consumer: `"dependency": ["xyo-cryptography"]` (DLL) or
  `["xyo-cryptography.static"]` (exports `XYO_CRYPTOGRAPHY_LIBRARY`).
  Install `xyo-system` and below to the SDK first (see the `fabricare`
  skill).
- Without fabricare: compile the seven amalgams (`Platform`,
  `ManagedMemory`, `DataStructures`, `Multithreading`, `Encoding`, `System`,
  `Cryptography`.Amalgam.cpp) with all seven `XYO_*_LIBRARY` defines (MSVC:
  also `/DXYO_PLATFORM_COMPILE_STATIC`), `-pthread` on Linux.
- Threads: initialize the registry in the main thread first
  (`XYO_APPLICATION_MAIN` or `Registry::registryInit()`); results are
  `String` / `Buffer`, owned by the creating thread.

## Code style (match the repository)

- Tabs (width 8), `.clang-format` in the repo, CRLF line endings; statements
  and blocks end with `};`.
- camelCase, `retV` for return values, trailing `_` for internal names and
  parameters that clash with members (`length_`, `seed_`).
- Headers: guard `XYO_CRYPTOGRAPHY_<NAME>_HPP`, guarded include of
  `Dependency.hpp`; add new headers to `source/XYO/Cryptography.hpp` and new
  `.cpp` files to `source/XYO/Cryptography.Amalgam.cpp`. OS specific code in
  `<Name>-OS-Windows.cpp` / `<Name>-OS-Linux.cpp` wrapped in
  `#ifdef XYO_PLATFORM_OS_WINDOWS` / `XYO_PLATFORM_OS_LINUX`. Exported
  symbols use `XYO_CRYPTOGRAPHY_EXPORT`. Free functions live in a
  sub-namespace (`Crypt::`, `Util::`).
- Functions that can fail return `bool` and assign outputs only on success.
- Never change the `Crypt` format or the hash output: existing encrypted
  files and published digests depend on them.
- SPDX header: MIT for `source/`, Unlicense for `test/`.
- Tests: `test/test.NN.cpp` with a `test()` that throws
  `std::runtime_error`, plus the name in the `"category": "test"` project of
  `fabricare.json`; run `fabricare make` then `fabricare test` (tests link
  the installed SDK otherwise). Check Linux code (`SystemRandom-OS-Linux.cpp`)
  with a WSL build.
