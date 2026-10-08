# Crypt

`Crypt` encrypts a block of bytes with a 64 byte key and signs the result,
so `decrypt` either returns exactly the original bytes or fails. It is the
format behind the `file-crypt` tool and the `quantum-script` `Crypt`
extension.

```cpp
namespace XYO::Cryptography::Crypt {
	void encrypt(const uint8_t *password, size_t passwordSize, const uint8_t *data, size_t dataSize, Buffer &output);
	bool decrypt(const uint8_t *password, size_t passwordSize, const uint8_t *data, size_t dataSize, Buffer &output);
	bool encryptFile(const uint8_t *password, size_t passwordSize, const char *fileNameIn, const char *fileNameOut);
	bool decryptFile(const uint8_t *password, size_t passwordSize, const char *fileNameIn, const char *fileNameOut);
	bool checkIntegrity(const uint8_t *password, size_t passwordSize, const uint8_t *data, size_t dataSize, const uint8_t *integrity);
};
```

Read [What it is not](README.md#what-it-is-not) before using it for new
data.

## Keys

The parameter is named `password`, but **`Crypt` expects key bytes, not
the text a user typed**. It uses the bytes as given; it does not hash,
stretch or check them. The convention of every XYO tool is:

```cpp
uint8_t key[64];
SHA512::hashToU8(passwordText, key);   // passwordText is a String
Crypt::encrypt(key, 64, data, dataSize, output);
```

Ways to get the 64 bytes:

| Source | Code | Strength |
|--------|------|----------|
| A password | `SHA512::hashToU8(password, key)` | only as strong as the password: one SHA512 is fast to guess |
| A random key | `SystemRandom::generate(key, 64)`, store it in a key file | full strength, the key file must be kept safe |
| A key file | `Shell::fileGetContents(name, keyBuffer)` and pass `keyBuffer.buffer`, `keyBuffer.length` | as the file |
| A key from a real KDF | Argon2 / scrypt / PBKDF2 output, 64 bytes | strong, but other XYO tools will not derive the same key |

Any length works technically, but use 64 bytes: shorter keys are weaker
and other tools (`file-crypt`) assume 64.

Encryption and decryption must derive the key the same way. A key made
from `"secret"` by `SHA512::hashToU8` does not open data encrypted with the
6 raw bytes `"secret"` (which `test/test.04.cpp` passes directly, for
brevity).

## Buffers

```cpp
uint8_t key[64];
SHA512::hashToU8("correct horse battery staple", key);

String text("attack at dawn");
Buffer encrypted;
Crypt::encrypt(key, 64, reinterpret_cast<const uint8_t *>(text.value()), text.length(), encrypted);

Buffer decrypted;
if (!Crypt::decrypt(key, 64, encrypted.buffer, encrypted.length, decrypted)) {
	// wrong key, modified, truncated or not Crypt data: nothing was decrypted
	return;
};
String back = decrypted.toString();
```

- `encrypt` cannot fail and has no return value. `output` is resized; its
  previous content is lost. `output.length` is the encrypted size.
- `decrypt` returns `false` for a wrong key, any changed byte, a changed
  length, truncated input or input shorter than 136 bytes. The signature is
  checked **before** anything is decrypted, so `output` is only written
  on success.
- Encrypting the same data twice gives different output (random seed).
- The input and the output must not be the same `Buffer`.
- The whole message is processed in memory at once: there is no streaming
  form.

Encrypted size for `n` input bytes:

```
136 + (n / 64 + 1) * 64      // 0..63 -> 200, 64..127 -> 264, ...
```

so the overhead is between 137 and 200 bytes.

## Files

```cpp
uint8_t key[64];
SHA512::hashToU8(password, key);

if (!Crypt::encryptFile(key, 64, "notes.txt", "notes.txt.crypt")) {
	// could not read the input or write the output
};
if (!Crypt::decryptFile(key, 64, "notes.txt.crypt", "notes.txt")) {
	// could not read, wrong key or damaged: the output file is not written
};
```

Both read the whole input file into memory, so they suit files that fit in
RAM. `decryptFile` writes the output only after `decrypt` succeeded; a
failed decryption never leaves a partial or garbage file. The output file is
overwritten if it exists.

From the command line the same format is produced by `file-crypt`.

## Checking a known version: checkIntegrity

Bytes 64 to 127 of encrypted data are its signature: a keyed SHA512 of
everything else. `checkIntegrity` answers *"is this exactly the encrypted
file I signed off earlier, and is it intact?"* without decrypting it:

```cpp
// when the file is accepted, keep its signature (it reveals nothing about the content)
uint8_t signature[64];
memcpy(signature, &encrypted.buffer[64], 64);

// later
if (Crypt::checkIntegrity(key, 64, data.buffer, data.length, signature)) {
	// valid for this key AND the same encryption as before
};
```

It returns `true` only when the signature verifies with the key **and**
equals `integrity`. Passing the data's own signature
(`&data.buffer[64]`) checks only that the data is intact for this key, like
`decrypt` without the output.

## Format

All encrypted data has this layout:

```
offset  size         content
0       64           seed: SHA512(key || data || time in ms || 64 bytes from SystemRandom)
64      64           signature: SHA512(seed || keyBase || encrypted length || encrypted data)
128     8            data length, little endian, encrypted
136     m * 64       data, encrypted, padded; m = n / 64 + 1
```

where

```
keyBase      = SHA512(seed || key)
stream(c)    = SHA512(seed || keyBase || c)      c = 64-bit little endian counter
length field = n XOR stream(0) XOR stream(1)
block i      = data[i] XOR stream(2 + 2i) XOR stream(3 + 2i)
```

- The seed is public and different for every encryption; it makes each
  key stream unique even for the same key and data. If the operating system
  generator fails, the seed still uses the time and the data.
- `keyBase` depends on the key and is never stored; without it neither the
  key stream nor the signature can be computed.
- The signature covers the length and all the blocks, so the length is
  validated before it is used (`decrypt` also rejects lengths that do not
  fit the input, see `test/test.06.cpp`).

## Security notes

- This is a custom design with a SHA512 based stream cipher and signature,
  not a standard AEAD. It is tested, not externally reviewed.
- The signature check uses `memcmp`, which is not constant time.
- Password keys are one SHA512 with no salt or work factor: an attacker
  who has the file can try billions of passwords per second on a GPU. Use
  long passphrases or random key files.
- The length of the message is hidden only to within 64 bytes.
- Keep `key` arrays short lived and clear them (`memset`) after use if
  that matters to you; the library does not keep copies.
