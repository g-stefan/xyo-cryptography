# API reference

Namespace `XYO::Cryptography` unless noted. Header: `<XYO/Cryptography.hpp>`
(umbrella) or the single header named in each section, under
`XYO/Cryptography/`.

## Macros

| Macro | Meaning |
|-------|---------|
| `XYO_CRYPTOGRAPHY_EXPORT` | dllexport while building the DLL (`XYO_CRYPTOGRAPHY_INTERNAL`), dllimport for users, empty with `XYO_CRYPTOGRAPHY_LIBRARY` |
| `XYO_CRYPTOGRAPHY_INTERNAL` | defined by the build when compiling this library |
| `XYO_CRYPTOGRAPHY_LIBRARY` | static linking, set for users of `xyo-cryptography.static` |

## Imported namespaces

`XYO::Cryptography` contains `using namespace` for `XYO::ManagedMemory`,
`XYO::DataStructures`, `XYO::Encoding`, `XYO::Multithreading` and
`XYO::System` (`Dependency.hpp`).

## MD5, SHA256, SHA512 : Object

`MD5.hpp`, `SHA256.hpp`, `SHA512.hpp`. Same members in all three; `T` is the
class. Not copyable, not movable. See [Hashing](hashing.md).

| Member | Description |
|--------|-------------|
| `T()` | ready to hash (calls `processInit()`) |
| `void processInit()` | reset to the start state |
| `void processU8(const uint8_t *toHash, size_t length)` | add `length` bytes, any split |
| `void processDone()` | add padding and length; call once, then read the result |
| `String getHashHex()` | digest as lowercase hex (32 / 64 / 128 chars) |
| `void toU8(uint8_t *buffer)` | digest as bytes (16 / 32 / 64), big endian words for SHA, little endian for MD5 (the standard byte order) |
| `void copy(const T &in)` | copy the whole state, also mid-message |
| `void hashBlock(uint32_t *w)` / `hashBlock(uint64_t *w)` (SHA512) | internal: compress one block of 16 words |
| `static String hash(const String &toHash)` | one call, hex; hashes `toHash.length()` bytes |
| `static void hashToU8(const String &toHash, uint8_t *buffer)` | one call, raw digest |

## Util

`Util.hpp`, namespace `XYO::Cryptography::Util`.

| Function | Description |
|----------|-------------|
| `bool fileHashSHA256(const char *fileName, String &hash)` | lowercase hex SHA256 of a file; `false` if it cannot be opened, sized or read completely |
| `bool fileHashSHA512(const char *fileName, String &hash)` | same, SHA512 |

`hash` is assigned only on success.

## Crypt

`Crypt.hpp`, namespace `XYO::Cryptography::Crypt`. `password` is key bytes,
normally the 64 byte `SHA512::hashToU8` of the user's password; see
[Crypt](crypt.md).

| Function | Description |
|----------|-------------|
| `void encrypt(const uint8_t *password, size_t passwordSize, const uint8_t *data, size_t dataSize, Buffer &output)` | `output` = seed, signature, encrypted length and data; `136 + (dataSize / 64 + 1) * 64` bytes |
| `bool decrypt(const uint8_t *password, size_t passwordSize, const uint8_t *data, size_t dataSize, Buffer &output)` | verify, then decrypt into `output`; `false` (and `output` untouched) on wrong key or damaged data |
| `bool encryptFile(const uint8_t *password, size_t passwordSize, const char *fileNameIn, const char *fileNameOut)` | read, `encrypt`, write; `false` on I/O error |
| `bool decryptFile(const uint8_t *password, size_t passwordSize, const char *fileNameIn, const char *fileNameOut)` | read, `decrypt`, write only on success |
| `bool checkIntegrity(const uint8_t *password, size_t passwordSize, const uint8_t *data, size_t dataSize, const uint8_t *integrity)` | `true` if the signature verifies with the key and equals the 64 bytes at `integrity` |

## SystemRandom

`SystemRandom.hpp`, namespace `XYO::Cryptography::SystemRandom`.

| Function | Description |
|----------|-------------|
| `bool generate(uint8_t *buffer, size_t length)` | fill with random bytes from the OS (`BCryptGenRandom` / `getrandom` / `/dev/urandom`); `false` if none works, buffer then undefined |

## RandomMT : Object

`RandomMT.hpp`. Mersenne Twister MT19937. Not copyable, not movable. Not
for secrets. See [Random numbers](random.md).

| Member | Description |
|--------|-------------|
| `RandomMT()` | seeded with `time(nullptr)` |
| `void seed(uint32_t)` | restart the sequence; `0` means `time(nullptr)` |
| `uint32_t nextRandom()` | next value; same sequence as `std::mt19937` for the same non zero seed |
| `uint32_t getValue()` | last value returned (the seed right after `seed`) |
| `void copy(RandomMT &value)` | copy the full state |

## xor8

`XOR8.hpp`.

| Function | Description |
|----------|-------------|
| `void xor8(uint8_t *inOut, size_t inOutLn, const uint8_t *key, size_t keyLn)` | `inOut[i] ^= key[i]` for `i < min(inOutLn, keyLn)`; the key is not repeated |

## Avalanche

`Avalanche.hpp`, namespace `XYO::Cryptography::Avalanche`. See
[Byte transforms](transforms.md).

| Function | Description |
|----------|-------------|
| `void encode(uint8_t *data, size_t dataLn)` | in place running XOR: `data[i + 1] ^= data[i]`, left to right |
| `void decode(uint8_t *data, size_t dataLn)` | inverse of `encode` |

## Library metadata

| Function | Description |
|----------|-------------|
| `const char *Version::version()` | e.g. `"5.0.0"` |
| `const char *Version::build()` | build number |
| `const char *Version::versionWithBuild()` | version and build |
| `const char *Version::datetime()` | build date and time |
| `const char *Copyright::copyright()`, `publisher()`, `company()`, `contact()` | copyright information |
| `std::string License::license()`, `shortLicense()` | MIT license text |

Qualify them in full (`XYO::Cryptography::Version::version()`): every XYO
library has the same names.
