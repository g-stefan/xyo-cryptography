# Hashing

`MD5`, `SHA256` and `SHA512` share one interface. Pick the class, then use
the one call form for data you already have, or the streaming form for data
that arrives in pieces.

| Class | Standard | Digest | Hex | Block | Use for |
|-------|----------|--------|-----|-------|---------|
| `SHA256` | FIPS 180-4 | 32 bytes | 64 chars | 64 bytes | general purpose hashing, fingerprints, checksums |
| `SHA512` | FIPS 180-4 | 64 bytes | 128 chars | 128 bytes | `Crypt` keys, release manifests, faster than SHA256 on 64-bit CPUs |
| `MD5` | RFC 1321 | 16 bytes | 32 chars | 64 bytes | legacy checksums only, **not** for security |

All three are tested against the published known answers
(`test/test.01.cpp` .. `test.03.cpp`) and against every way of splitting
the input (`test/test.05.cpp`).

## One call

```cpp
String hex = SHA256::hash("The quick brown fox jumps over the lazy dog");
// "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"

uint8_t digest[64];
SHA512::hashToU8("secret", digest);  // raw bytes, 64 for SHA512
```

- `hash(const String &)` returns the digest as **lowercase hex**.
- `hashToU8(const String &, uint8_t *buffer)` writes the raw digest;
  `buffer` must hold 16 (MD5), 32 (SHA256) or 64 (SHA512) bytes.
- Both hash `toHash.length()` bytes, so a `String` holding binary data
  (`String(ptr, len)`, `Buffer::toString()`) is hashed completely, `0`
  bytes included. A `const char *` argument is first turned into a
  `String`, which stops at the first `0`.

## Streaming

```cpp
SHA512 hash;                       // the constructor calls processInit()
hash.processU8(part1, part1Size);  // any number of times, any sizes
hash.processU8(part2, part2Size);
hash.processDone();                // padding and length, once

String hex = hash.getHashHex();    // lowercase hex
uint8_t digest[64];
hash.toU8(digest);                 // raw bytes
```

Life cycle of a hash object:

```
processInit()  ->  processU8() ... processU8()  ->  processDone()  ->  getHashHex() / toU8() ...
     ^                                                                        |
     +------------------------------ reuse ----------------------------------+
```

- **`processDone()` exactly once.** It appends the padding through
  `processU8`; a second call, or more `processU8` after it, gives a wrong
  digest without any error.
- `getHashHex()` and `toU8()` only read the result; call them as often as
  needed after `processDone()`.
- To hash something else with the same object call `processInit()` first.
- The split does not matter: one call with 300 bytes or 300 calls with one
  byte give the same digest.
- `hashBlock()` is public because `Crypt` and the derived state need it; do
  not call it, it skips the buffering and the length count.

## Copying the state

The hash classes cannot be copied with `=` or a copy constructor
(`XYO_PLATFORM_DISALLOW_COPY_ASSIGN_MOVE`). `copy(const T &)` copies the
whole state, even in the middle of a message. Two uses:

**A common prefix hashed once.** `Crypt` does this for every 64 byte block:

```cpp
SHA512 prefix;
prefix.processU8(key, 64);           // hashed once

SHA512 block;
for (uint64_t counter = 0; counter < blocks; ++counter) {
	uint8_t counterBytes[8];
	UConvert::u64ToU8(counter, counterBytes);
	block.copy(prefix);              // continue from the prefix
	block.processU8(counterBytes, 8);
	block.processDone();
	block.toU8(output + counter * 64);
};
```

**The digest so far, without stopping.**

```cpp
SHA256 running;
running.processU8(data, n);

SHA256 snapshot;
snapshot.copy(running);
snapshot.processDone();              // digest of the data up to now
printf("%s\n", snapshot.getHashHex().value());

running.processU8(more, m);          // the original goes on
```

## Files

```cpp
String hex;
if (Util::fileHashSHA512("release.7z", hex)) {
	printf("%s\n", hex.value());
} else {
	// the file does not exist, cannot be opened, or was not read completely
};
```

`Util::fileHashSHA256` / `fileHashSHA512` read the file in 32 KB blocks,
so memory does not grow with the file. They compare the bytes hashed with
the file size and return `false` on a short read, instead of a digest of
part of the file. Files that change while they are hashed may also fail.

There is no `Util` function for MD5; stream the file yourself with `File`
from `xyo-system`:

```cpp
bool fileHashMD5(const char *fileName, String &hex) {
	File file;
	if (!file.openRead(fileName)) {
		return false;
	};
	MD5 hash;
	uint8_t buffer[32768];
	size_t ln;
	do {
		ln = file.read(buffer, sizeof(buffer));
		hash.processU8(buffer, ln);
	} while (ln == sizeof(buffer));
	file.close();
	hash.processDone();
	hex = hash.getHashHex();
	return true;
};
```

(This short version does not tell a read error from the end of the file;
`Util.cpp` shows how to check the size.)

## Formats

| You have | You want | How |
|----------|----------|-----|
| raw digest `uint8_t d[32]` | hex | `Buffer b; b.set(d, 32); b.toHex()` (lowercase) |
| raw digest | Base64 | `Base64::encode(String(reinterpret_cast<const char *>(d), 32))` |
| hex | raw digest | `Buffer b; b.fromHex(hex);` or `Base16::decode(hex, out)` (`false` if invalid) |
| uppercase hex from elsewhere | compare with `getHashHex()` | `other.toLowerCaseASCII() == hex` |

The hex from this library is always lowercase. Compare a stored digest
with `==` on the hex strings, or `memcmp` on the raw bytes.

## Recipe: verify a download

```cpp
// manifest line: "<sha512 hex> <file name>"
bool verify(const char *fileName, const String &expectedHex) {
	String actual;
	if (!Util::fileHashSHA512(fileName, actual)) {
		return false;
	};
	return actual == expectedHex.trimASCII().toLowerCaseASCII();
};
```

## Recipe: keyed hash (HMAC)

Never authenticate a message with `SHA256(key || message)`: SHA-2 allows
*length extension*, anyone who sees that digest can compute the digest of
`key || message || padding || more` without the key. Use HMAC (RFC 2104).
The library has no HMAC function, but the streaming interface is enough:

```cpp
// HMAC-SHA256, out receives 32 bytes
void hmacSHA256(const uint8_t *key, size_t keyLn, const uint8_t *message, size_t messageLn, uint8_t *out) {
	uint8_t block[64];  // SHA256 block size (128 for SHA512)
	memset(block, 0, sizeof(block));
	if (keyLn > sizeof(block)) {
		SHA256 keyHash;
		keyHash.processU8(key, keyLn);
		keyHash.processDone();
		keyHash.toU8(block);
	} else {
		memcpy(block, key, keyLn);
	};

	uint8_t pad[64];
	uint8_t inner[32];
	size_t k;

	for (k = 0; k < sizeof(pad); ++k) {
		pad[k] = block[k] ^ 0x36;
	};
	SHA256 hash;
	hash.processU8(pad, sizeof(pad));
	hash.processU8(message, messageLn);
	hash.processDone();
	hash.toU8(inner);

	for (k = 0; k < sizeof(pad); ++k) {
		pad[k] = block[k] ^ 0x5C;
	};
	hash.processInit();
	hash.processU8(pad, sizeof(pad));
	hash.processU8(inner, sizeof(inner));
	hash.processDone();
	hash.toU8(out);
};
```

RFC 4231 test case 2 (key `"Jefe"`, message `"what do ya want for
nothing?"`) gives
`5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843`.

## Pitfalls

- **Do not store passwords as a plain hash.** A single SHA-2 of a password
  is fast to brute force. Use a password hashing function (Argon2, scrypt,
  bcrypt, PBKDF2 from OpenSSL) for stored passwords. `Crypt` uses
  `SHA512(password)` as its key, see [Crypt](crypt.md#keys).
- **MD5** has practical collisions: two different files with the same MD5
  can be made on purpose. Use it only where nobody gains from that.
- **`String` from `printf`**: pass `hex.value()`, not `hex`.
- `toU8` writes the full digest size; give it a buffer that large.
- One object is not thread safe; use one per thread (they are small and
  live well on the stack).
