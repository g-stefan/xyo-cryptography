// Created by Grigore Stefan <g_stefan@yahoo.com>
// Public domain (Unlicense) <http://unlicense.org>
// SPDX-FileCopyrightText: 2016-2026 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: Unlicense

#include <XYO/Cryptography.hpp>

using namespace XYO::Cryptography;

// Streaming: processU8 called several times must give the same hash as one call

template <typename THash>
String hashChunked(const uint8_t *input, size_t length, size_t chunk) {
	THash hash;
	size_t k;
	size_t ln;
	for (k = 0; k < length; k += chunk) {
		ln = length - k;
		if (ln > chunk) {
			ln = chunk;
		};
		hash.processU8(&input[k], ln);
	};
	hash.processDone();
	return hash.getHashHex();
};

template <typename THash>
void testStreaming(const char *name) {
	uint8_t input[300];
	size_t length;
	size_t split;
	size_t chunk;
	char buffer[1024];

	for (length = 0; length < sizeof(input); ++length) {
		input[length] = (uint8_t)(length * 7 + 3);
	};

	for (length = 0; length <= sizeof(input); ++length) {
		THash oneShot;
		oneShot.processU8(input, length);
		oneShot.processDone();
		String expected = oneShot.getHashHex();

		for (split = 0; split <= length; ++split) {
			THash hash;
			hash.processU8(input, split);
			hash.processU8(&input[split], length - split);
			hash.processDone();
			if (hash.getHashHex() != expected) {
				sprintf(buffer, "%s streaming mismatch, length %zu split at %zu", name, length, split);
				throw(std::runtime_error(buffer));
			};
		};

		for (chunk = 1; chunk <= 17; ++chunk) {
			if (hashChunked<THash>(input, length, chunk) != expected) {
				sprintf(buffer, "%s streaming mismatch, length %zu chunk size %zu", name, length, chunk);
				throw(std::runtime_error(buffer));
			};
		};
	};
};

void testKnownAnswer() {
	SHA256 hash;
	hash.processU8(reinterpret_cast<const uint8_t *>("a"), 1);
	hash.processU8(reinterpret_cast<const uint8_t *>("bcde"), 4);
	hash.processDone();
	if (hash.getHashHex() != "36bbe50ed96841d10443bcb670d6554f0a34b761be67ec9c4a8ad2c0c44ca42c") {
		throw(std::runtime_error("SHA256 streaming \"a\" + \"bcde\""));
	};
};

void test() {
	testKnownAnswer();
	testStreaming<MD5>("MD5");
	testStreaming<SHA256>("SHA256");
	testStreaming<SHA512>("SHA512");
};

int main(int cmdN, char *cmdS[]) {

	try {
		test();
		return 0;
	} catch (const std::exception &e) {
		printf("* Error: %s\n", e.what());
	} catch (...) {
		printf("* Error: Unknown\n");
	};

	return 1;
};
