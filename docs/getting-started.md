# Getting started

## 1. Build and install

The library is built with [fabricare](https://github.com/g-stefan/fabricare),
the build tool used by all XYO C++ projects. `xyo-system` and the libraries
under it (`xyo-platform`, `xyo-managed-memory`, `xyo-data-structures`,
`xyo-multithreading`, `xyo-encoding`) must be installed to the SDK first.
From the repository root:

```bash
fabricare make       # build into output/
fabricare test       # build and run test/test.*.cpp (run make first)
fabricare install    # copy output/{bin,include,lib} to ~/.fabricare/<platform>
fabricare clean      # remove output/ and temp/
```

Two libraries are produced:

| Project                    | Kind                                | Use it when                               |
|----------------------------|-------------------------------------|-------------------------------------------|
| `xyo-cryptography`         | DLL / shared library (`dll-or-lib`) | default, shared between several programs  |
| `xyo-cryptography.static`  | static library, static CRT          | self-contained executables                |

Nothing in this library is header only: every class and function lives in
the compiled part.

## 2. Depend on it from another fabricare project

In the consumer's `fabricare.json`:

```json
{
	"name": "my-tool",
	"make": "exe",
	"sourcePath": "XYO/MyTool",
	"dependency": [
		"xyo-cryptography"
	]
}
```

For the static variant use `"xyo-cryptography.static"`. It exports
`XYO_CRYPTOGRAPHY_LIBRARY` to the consumer (`dependencyDefines`), which turns
`XYO_CRYPTOGRAPHY_EXPORT` into nothing. `xyo-system` and everything below it
come in as transitive dependencies.

## 3. Include

```cpp
#include <XYO/Cryptography.hpp>
```

The umbrella header pulls in `<XYO/System.hpp>` (and through it every lower
XYO layer) and every public header of this library.

Namespace `XYO::Cryptography` contains `using namespace` for
`XYO::ManagedMemory`, `XYO::DataStructures`, `XYO::Encoding`,
`XYO::Multithreading` and `XYO::System`, so `using namespace
XYO::Cryptography;` also brings in `String`, `Buffer`, `File`, `Shell`,
`UConvert`, `TPointer`, ... The metadata namespaces then exist several times
(`Version`, `Copyright`, `License`): write
`XYO::Cryptography::Version::version()` in full.

Sub-namespaces group the free functions: `Crypt::`, `SystemRandom::`,
`Avalanche::`, `Util::`. `xor8` is directly in `XYO::Cryptography`. The
classes `MD5`, `SHA256`, `SHA512` and `RandomMT` are in `XYO::Cryptography`.

## 4. First program

Hash a string two ways, encrypt and decrypt a message with a password, and
make a random salt.

```cpp
#include <XYO/Cryptography.hpp>

using namespace XYO::Cryptography;

int main(int, char *[]) {
	// 1. one call hash of a string, lowercase hex
	printf("sha256: %s\n", SHA256::hash("abc").value());

	// 2. the same hash, data given in pieces
	SHA256 hash;
	hash.processU8(reinterpret_cast<const uint8_t *>("a"), 1);
	hash.processU8(reinterpret_cast<const uint8_t *>("bc"), 2);
	hash.processDone();
	printf("sha256: %s\n", hash.getHashHex().value());

	// 3. encrypt with a password: Crypt takes the SHA512 of the password, 64 bytes
	uint8_t key[64];
	SHA512::hashToU8("my password", key);

	String message("Hello World!");
	Buffer encrypted;
	Crypt::encrypt(key, sizeof(key), reinterpret_cast<const uint8_t *>(message.value()), message.length(), encrypted);
	printf("encrypted: %zu bytes\n", encrypted.length); // 64 + 64 + 8 + 64 = 200

	Buffer decrypted;
	if (Crypt::decrypt(key, sizeof(key), encrypted.buffer, encrypted.length, decrypted)) {
		printf("decrypted: %s\n", decrypted.toString().value());
	};

	// 4. random bytes from the operating system
	Buffer salt;
	salt.setSize(16);
	salt.length = salt.size;
	if (SystemRandom::generate(salt.buffer, salt.length)) {
		printf("salt: %s\n", salt.toHex().value());
	};

	return 0;
};
```

Output (the salt changes on every run):

```
sha256: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
sha256: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
encrypted: 200 bytes
decrypted: Hello World!
salt: bf7cc2d2fcd6d71053d795453a5cbf3f
```

Things to notice, all explained in the following pages:

- the hash classes take `const uint8_t *`; cast text with
  `reinterpret_cast<const uint8_t *>(s.value())` and pass `s.length()`;
- `processDone()` finishes the hash, after it read the result with
  `getHashHex()` or `toU8()`;
- **`Crypt` never sees the password**, only its 64 byte SHA512. Encrypt
  and decrypt must hash the password the same way;
- `Buffer::setSize` allocates, `length` is the number of bytes in use; set
  it yourself when you fill the buffer directly.

As a fabricare test project:

```json
{
	"name": "test.09",
	"make": "exe",
	"category": "test",
	"SPDX-License-Identifier": "Unlicense",
	"dependency": [
		"xyo-cryptography"
	]
}
```

with the source in `test/test.09.cpp`.

For a full application use the `xyo-system` entry point
(`XYO_APPLICATION_MAIN`), which also initializes the managed memory
registry; see the `xyo-system` documentation.

## 5. Threads

- Every hash object (`MD5`, `SHA256`, `SHA512`) and every `RandomMT` holds
  mutable state with no locking: **use one object per thread**, or protect
  it yourself.
- The free functions (`SHA256::hash`, `SHA512::hashToU8`, `Crypt::*`,
  `Util::*`, `SystemRandom::generate`, `xor8`, `Avalanche::*`) have no
  shared state and can run on several threads at once.
- The results are `String` and `Buffer`, managed objects that belong to the
  thread that created them (see the `xyo-managed-memory` and `xyo-encoding`
  documentation). To hand a hash to another thread, copy the bytes
  (`toU8` into a plain array) or the characters, not the `String`.
- Create threads with `xyo-multithreading`, and initialize the registry in
  the main thread first (`XYO_APPLICATION_MAIN` does it, or call
  `XYO::ManagedMemory::Registry::registryInit()` at the start of `main`).

## 6. Building without fabricare

Compile the seven amalgams with your sources:

1. Put `source/` of `xyo-platform`, `xyo-managed-memory`,
   `xyo-data-structures`, `xyo-multithreading`, `xyo-encoding`,
   `xyo-system` and `xyo-cryptography` on the include path.
2. Provide the configuration headers of the lower layers (see the
   `xyo-system` getting started page). This library has none of its own.
3. Compile `Platform.Amalgam.cpp`, `ManagedMemory.Amalgam.cpp`,
   `DataStructures.Amalgam.cpp`, `Multithreading.Amalgam.cpp`,
   `Encoding.Amalgam.cpp`, `System.Amalgam.cpp` and
   `Cryptography.Amalgam.cpp` together with your sources, and define
   `XYO_PLATFORM_LIBRARY`, `XYO_MANAGEDMEMORY_LIBRARY`,
   `XYO_DATASTRUCTURES_LIBRARY`, `XYO_MULTITHREADING_LIBRARY`,
   `XYO_ENCODING_LIBRARY`, `XYO_SYSTEM_LIBRARY` and
   `XYO_CRYPTOGRAPHY_LIBRARY` everywhere (plain static linking).
4. Link `pthread` on Linux. On Windows no extra library is needed:
   `SystemRandom` loads `bcrypt.dll` from `System32` at run time.

Example on Linux, with the repositories side by side:

```bash
g++ -std=c++17 \
    -Ixyo-platform/source -Ixyo-managed-memory/source \
    -Ixyo-data-structures/source -Ixyo-multithreading/source \
    -Ixyo-encoding/source -Ixyo-system/source -Ixyo-cryptography/source \
    -DXYO_PLATFORM_LIBRARY -DXYO_MANAGEDMEMORY_LIBRARY \
    -DXYO_DATASTRUCTURES_LIBRARY -DXYO_MULTITHREADING_LIBRARY \
    -DXYO_ENCODING_LIBRARY -DXYO_SYSTEM_LIBRARY -DXYO_CRYPTOGRAPHY_LIBRARY \
    xyo-platform/source/XYO/Platform.Amalgam.cpp \
    xyo-managed-memory/source/XYO/ManagedMemory.Amalgam.cpp \
    xyo-data-structures/source/XYO/DataStructures.Amalgam.cpp \
    xyo-multithreading/source/XYO/Multithreading.Amalgam.cpp \
    xyo-encoding/source/XYO/Encoding.Amalgam.cpp \
    xyo-system/source/XYO/System.Amalgam.cpp \
    xyo-cryptography/source/XYO/Cryptography.Amalgam.cpp \
    main.cpp -o main -pthread
```

On Windows with MSVC, also define `XYO_PLATFORM_COMPILE_STATIC`:

```bat
cl /EHsc /std:c++17 ^
   /Ixyo-platform\source /Ixyo-managed-memory\source ^
   /Ixyo-data-structures\source /Ixyo-multithreading\source ^
   /Ixyo-encoding\source /Ixyo-system\source /Ixyo-cryptography\source ^
   /DXYO_PLATFORM_COMPILE_STATIC /DXYO_PLATFORM_LIBRARY /DXYO_MANAGEDMEMORY_LIBRARY ^
   /DXYO_DATASTRUCTURES_LIBRARY /DXYO_MULTITHREADING_LIBRARY ^
   /DXYO_ENCODING_LIBRARY /DXYO_SYSTEM_LIBRARY /DXYO_CRYPTOGRAPHY_LIBRARY ^
   xyo-platform\source\XYO\Platform.Amalgam.cpp ^
   xyo-managed-memory\source\XYO\ManagedMemory.Amalgam.cpp ^
   xyo-data-structures\source\XYO\DataStructures.Amalgam.cpp ^
   xyo-multithreading\source\XYO\Multithreading.Amalgam.cpp ^
   xyo-encoding\source\XYO\Encoding.Amalgam.cpp ^
   xyo-system\source\XYO\System.Amalgam.cpp ^
   xyo-cryptography\source\XYO\Cryptography.Amalgam.cpp ^
   main.cpp
```

With an installed SDK (`~/.fabricare/<platform>`) you can instead compile
only your sources against `include/` and link the `*.static` libraries
(static CRT, `/MT`), from `xyo-cryptography.static` down to
`xyo-platform.static`.
