// Created by Grigore Stefan <g_stefan@yahoo.com>
// Public domain (Unlicense) <http://unlicense.org>
// SPDX-FileCopyrightText: 2016-2026 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: Unlicense

#include <XYO/Cryptography.hpp>

using namespace XYO::Cryptography;

// Crypt: round trip for many sizes, tampered input must be rejected (and not crash)

static const char *password = "secret";
static const size_t passwordSize = 6;

static const size_t headerSize = 64 + 64 + 8;

bool decryptBuffer(const Buffer &encrypted, const char *password_, size_t passwordSize_) {
	Buffer decrypted;
	return Crypt::decrypt(reinterpret_cast<const uint8_t *>(password_), passwordSize_, encrypted.buffer, encrypted.length, decrypted);
};

bool checkIntegrityBuffer(const Buffer &encrypted) {
	return Crypt::checkIntegrity(reinterpret_cast<const uint8_t *>(password), passwordSize, encrypted.buffer, encrypted.length, &encrypted.buffer[64]);
};

void expectRejected(const Buffer &encrypted, const char *what, size_t dataSize) {
	char buffer[1024];
	if (decryptBuffer(encrypted, password, passwordSize)) {
		sprintf(buffer, "decrypt accepted %s, data size %zu", what, dataSize);
		throw(std::runtime_error(buffer));
	};
	if (encrypted.length >= headerSize) {
		if (checkIntegrityBuffer(encrypted)) {
			sprintf(buffer, "checkIntegrity accepted %s, data size %zu", what, dataSize);
			throw(std::runtime_error(buffer));
		};
	};
};

void testTamper(const uint8_t *data, size_t dataSize) {
	char buffer[1024];
	Buffer encrypted;
	Buffer tampered;
	size_t k;

	Crypt::encrypt(reinterpret_cast<const uint8_t *>(password), passwordSize, data, dataSize, encrypted);

	{
		Buffer decrypted;
		if (!Crypt::decrypt(reinterpret_cast<const uint8_t *>(password), passwordSize, encrypted.buffer, encrypted.length, decrypted)) {
			sprintf(buffer, "decrypt, data size %zu", dataSize);
			throw(std::runtime_error(buffer));
		};
		if (decrypted.length != dataSize || (dataSize > 0 && memcmp(decrypted.buffer, data, dataSize) != 0)) {
			sprintf(buffer, "decrypt check, data size %zu", dataSize);
			throw(std::runtime_error(buffer));
		};
		if (!checkIntegrityBuffer(encrypted)) {
			sprintf(buffer, "check integrity, data size %zu", dataSize);
			throw(std::runtime_error(buffer));
		};
	};

	// wrong password
	if (decryptBuffer(encrypted, "Secret", passwordSize)) {
		sprintf(buffer, "decrypt accepted wrong password, data size %zu", dataSize);
		throw(std::runtime_error(buffer));
	};

	// every bit of the encrypted length field
	for (k = 0; k < 64; ++k) {
		tampered.set(encrypted.buffer, encrypted.length);
		tampered.buffer[64 + 64 + k / 8] ^= (uint8_t)(1 << (k % 8));
		expectRejected(tampered, "length bit flip", dataSize);
	};

	// length field forged to wrap the size computation, the length is XOR encrypted,
	// its high bits are known from the file size
	uint64_t highBits = (uint64_t)(dataSize / 64);
	for (k = 0; k < 4; ++k) {
		uint64_t forgedHighBits = ((((uint64_t)1) << 58) - 1) - k;
		uint8_t delta[8];
		UConvert::u64ToU8((highBits ^ forgedHighBits) << 6, delta);
		tampered.set(encrypted.buffer, encrypted.length);
		xor8(&tampered.buffer[64 + 64], 8, delta, 8);
		expectRejected(tampered, "forged length", dataSize);
	};

	// salt, signature, first and last data byte
	size_t positions[4] = {0, 64, headerSize, encrypted.length - 1};
	for (k = 0; k < 4; ++k) {
		tampered.set(encrypted.buffer, encrypted.length);
		tampered.buffer[positions[k]] ^= 0x01;
		expectRejected(tampered, "modified byte", dataSize);
	};

	// truncated
	tampered.set(encrypted.buffer, encrypted.length - 1);
	expectRejected(tampered, "truncated input", dataSize);
	tampered.set(encrypted.buffer, headerSize - 1);
	expectRejected(tampered, "input shorter than header", dataSize);
};

void test() {
	uint8_t data[200];
	size_t k;
	for (k = 0; k < sizeof(data); ++k) {
		data[k] = (uint8_t)(k * 13 + 5);
	};
	for (k = 0; k <= sizeof(data); ++k) {
		testTamper(data, k);
	};
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
