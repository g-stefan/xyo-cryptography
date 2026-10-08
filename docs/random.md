# Random numbers

Two generators, for two different jobs:

| | `SystemRandom` | `RandomMT` |
|-|----------------|------------|
| Source | the operating system generator | Mersenne Twister MT19937, in process |
| Unpredictable | yes | **no**: 624 outputs reveal the state |
| Reproducible from a seed | no | yes, same sequence as `std::mt19937` |
| Speed | a system call per request | very fast |
| Can fail | yes, returns `false` | no |
| Use for | keys, salts, nonces, tokens, session ids, passwords | simulations, tests, shuffling, games, script `Random` |

When in doubt, use `SystemRandom`.

## SystemRandom

```cpp
uint8_t key[64];
if (!SystemRandom::generate(key, sizeof(key))) {
	// no working generator: do not continue with a weak key
	return false;
};
```

- **Windows**: `BCryptGenRandom` with the system preferred generator.
  `bcrypt.dll` is loaded from `System32` at run time, so the program does
  not link `bcrypt.lib`. Requests larger than 256 MB are split.
- **Linux**: the `getrandom` system call (works without the glibc wrapper,
  kernel 3.17+), falling back to reading `/dev/urandom`. Interrupted calls
  (`EINTR`) are retried.
- Returns `false` when no source works; the buffer content is then
  undefined. `generate(buffer, 0)` returns `true`.
- Thread safe: no state in the library.

Random values from the bytes:

```cpp
uint32_t randomU32() {
	uint8_t bytes[4];
	if (!SystemRandom::generate(bytes, 4)) {
		throw std::runtime_error("SystemRandom");
	};
	return UConvert::u32FromU8(bytes);
};

// uniform in [0, range), no modulo bias
uint32_t randomBelow(uint32_t range) {
	uint32_t limit = UINT32_MAX - (UINT32_MAX % range);  // largest multiple of range
	uint32_t value;
	do {
		value = randomU32();
	} while (value >= limit);
	return value % range;
};
```

A random token as text:

```cpp
uint8_t bytes[32];
SystemRandom::generate(bytes, sizeof(bytes));  // check the result in real code
Buffer token;
token.set(bytes, sizeof(bytes));
String hex = token.toHex();                    // 64 lowercase hex characters
```

## RandomMT

```cpp
RandomMT random;          // seeded from time(nullptr)
random.seed(12345);       // or a fixed seed: same sequence on every run and platform
uint32_t a = random.nextRandom();
uint32_t b = random.nextRandom();
uint32_t last = random.getValue();   // == b, does not advance
```

- `nextRandom()` returns the next 32-bit value of MT19937. For the same
  non zero seed the sequence equals `std::mt19937(seed)`.
- **`seed(0)` means "seed from the clock"** (`time(nullptr)`), like the
  constructor; it does not give the sequence of seed 0. Two generators made
  in the same second get the same sequence.
- `getValue()` returns the last value produced (after `seed(s)`, before the
  first `nextRandom()`, it returns `s`).
- `copy(RandomMT &)` copies the full state: the copy continues with the
  same numbers. The class cannot be copied with `=`.
- One object per thread, or lock it yourself.
- Seeding only takes 32 bits: there are at most 2^32 different sequences.

A number in a range, a float, a shuffle:

```cpp
uint32_t dice = 1 + random.nextRandom() % 6;              // tiny bias, fine for games
double unit = random.nextRandom() / 4294967296.0;         // [0, 1)

for (size_t k = count - 1; k > 0; --k) {                  // Fisher-Yates
	size_t j = random.nextRandom() % (k + 1);
	std::swap(items[k], items[j]);
};
```

To seed `RandomMT` unpredictably, take the seed from `SystemRandom` — the
output is still predictable once observed, so this is no substitute for
`SystemRandom` when the numbers must stay secret:

```cpp
uint8_t seedBytes[4];
if (SystemRandom::generate(seedBytes, 4)) {
	random.seed(UConvert::u32FromU8(seedBytes) | 1);  // never 0
};
```
