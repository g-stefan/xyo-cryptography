# Cryptography

C++ library
- Hash functions `MD5`, `SHA256` and `SHA512`, in one call or streaming, plus file hashing.
- `Crypt`: authenticated encryption of buffers and files with a 64 byte key (normally the
SHA512 of a password), the format used by `file-crypt`.
- Random numbers: `SystemRandom` (operating system generator, for keys and salts) and
`RandomMT` (Mersenne Twister, reproducible, not for secrets).
- Byte transforms `xor8` and `Avalanche`.

Built on `xyo-system`; used by `file-crypt`, `fabricare` and the `quantum-script`
extensions (`md5`, `sha256`, `sha512`, `crypt`, `random`).

## Documentation

- [Overview](docs/README.md) - purpose, design and limits
- [Getting started](docs/getting-started.md) - build, depend on it, first program, threads
- [Hashing](docs/hashing.md) - `MD5`, `SHA256`, `SHA512`, streaming, state copy, files, HMAC recipe
- [Crypt](docs/crypt.md) - encrypting buffers and files, keys, format, integrity, security notes
- [Random numbers](docs/random.md) - `SystemRandom`, `RandomMT`
- [Byte transforms](docs/transforms.md) - `xor8`, `Avalanche`
- [API reference](docs/reference.md)

A Claude Code skill for this library is in
[.claude/skills/xyo-cryptography](.claude/skills/xyo-cryptography/SKILL.md).

## License

Copyright (c) 2016-2026 Grigore Stefan
Licensed under the [MIT](LICENSE) license.
