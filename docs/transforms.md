# Byte transforms

Two small in place operations on byte arrays. Neither is encryption by
itself; they are building blocks (`Crypt` uses `xor8`).

## xor8

```cpp
void xor8(uint8_t *inOut, size_t inOutLn, const uint8_t *key, size_t keyLn);
```

XORs `inOut[i] ^= key[i]` for `i < min(inOutLn, keyLn)`.

- **The key is not repeated.** With a 2 byte key only the first 2 bytes of
  the data change:

  ```cpp
  uint8_t data[5] = {1, 2, 3, 4, 5};
  uint8_t key[2] = {0xFF, 0xFF};
  xor8(data, 5, key, 2);   // {254, 253, 3, 4, 5}
  ```

  To XOR a long buffer with a key stream, produce the stream in blocks
  and call `xor8` per block, as `Crypt` does with 64 byte SHA512 blocks.
- Applying the same key twice gives back the original.
- `inOut` and `key` may be the same array (the result is then zeros).
- XOR with a reused or predictable key is not secure: two messages XORed
  with the same key stream reveal the XOR of the messages.

## Avalanche

```cpp
namespace Avalanche {
	void encode(uint8_t *data, size_t dataLn);
	void decode(uint8_t *data, size_t dataLn);
};
```

`encode` replaces every byte with the XOR of itself and all the bytes
before it (a running XOR): a change in one byte changes that byte and every
byte after it. `decode` reverses it exactly.

```cpp
uint8_t v[4] = {1, 2, 4, 8};
Avalanche::encode(v, 4);   // {1, 3, 7, 15}
Avalanche::decode(v, 4);   // {1, 2, 4, 8}
```

- The first byte never changes; a change spreads forward only, never
  backward. Run it over reversed data, or twice in opposite directions, if
  you need diffusion both ways.
- It has no key: anyone can decode. It is a mixing step for data formats
  and light obfuscation, never a replacement for encryption.
- Empty input is fine (nothing happens).
