// Created by Grigore Stefan <g_stefan@yahoo.com>
// Public domain (Unlicense) <http://unlicense.org>
// SPDX-FileCopyrightText: 2016-2026 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: Unlicense

#include <XYO/Cryptography.hpp>

using namespace XYO::Cryptography;

// SystemRandom and the Crypt seed

void testSystemRandom() {
	uint8_t a[64];
	uint8_t b[64];
	static uint8_t large[1024 * 1024];

	if (!SystemRandom::generate(a, sizeof(a))) {
		throw(std::runtime_error("SystemRandom not available"));
	};
	if (!SystemRandom::generate(b, sizeof(b))) {
		throw(std::runtime_error("SystemRandom not available"));
	};
	if (memcmp(a, b, sizeof(a)) == 0) {
		throw(std::runtime_error("SystemRandom repeated"));
	};
	if (!SystemRandom::generate(a, 0)) {
		throw(std::runtime_error("SystemRandom zero length"));
	};
	if (!SystemRandom::generate(large, sizeof(large))) {
		throw(std::runtime_error("SystemRandom large buffer"));
	};
};

// Same password and data encrypted back to back, usually in the same millisecond:
// with SystemRandom in the seed the seeds must differ
void testSeed() {
	uint8_t password[64];
	const char *text = "Hello World!";
	size_t textSize = strlen(text);
	int k;

	SHA512::hashToU8("secret", password);

	for (k = 0; k < 16; ++k) {
		Buffer encrypted1;
		Buffer encrypted2;
		Buffer decrypted;
		Crypt::encrypt(password, sizeof(password), reinterpret_cast<const uint8_t *>(text), textSize, encrypted1);
		Crypt::encrypt(password, sizeof(password), reinterpret_cast<const uint8_t *>(text), textSize, encrypted2);
		if (memcmp(encrypted1.buffer, encrypted2.buffer, 64) == 0) {
			throw(std::runtime_error("seed repeated"));
		};
		if (!Crypt::decrypt(password, sizeof(password), encrypted1.buffer, encrypted1.length, decrypted)) {
			throw(std::runtime_error("decrypt 1"));
		};
		if (decrypted.toString() != text) {
			throw(std::runtime_error("decrypt check 1"));
		};
		if (!Crypt::decrypt(password, sizeof(password), encrypted2.buffer, encrypted2.length, decrypted)) {
			throw(std::runtime_error("decrypt 2"));
		};
		if (decrypted.toString() != text) {
			throw(std::runtime_error("decrypt check 2"));
		};
	};
};

void test() {
	testSystemRandom();
	testSeed();
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
