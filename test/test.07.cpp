// Created by Grigore Stefan <g_stefan@yahoo.com>
// Public domain (Unlicense) <http://unlicense.org>
// SPDX-FileCopyrightText: 2016-2026 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: Unlicense

#include <XYO/Cryptography.hpp>

using namespace XYO::Cryptography;

// Util: file hash must match the in memory hash, sizes around the 32768 read buffer

static const char *fileName = "test.07.tmp";

template <typename THash>
String memoryHash(const uint8_t *data, size_t length) {
	THash hash;
	hash.processU8(data, length);
	hash.processDone();
	return hash.getHashHex();
};

void writeFile(const uint8_t *data, size_t length) {
	File fileOut;
	if (!fileOut.openWrite(fileName)) {
		throw(std::runtime_error("open write"));
	};
	if (fileOut.write(data, length) != length) {
		throw(std::runtime_error("write"));
	};
	fileOut.close();
};

void test() {
	char buffer[1024];
	static const size_t sizes[] = {0, 1, 32767, 32768, 32769, 65536, 100000};
	static uint8_t data[100000];
	size_t k;
	String hash;

	for (k = 0; k < sizeof(data); ++k) {
		data[k] = (uint8_t)(k * 11 + 7);
	};

	for (k = 0; k < sizeof(sizes) / sizeof(sizes[0]); ++k) {
		writeFile(data, sizes[k]);

		if (!Util::fileHashSHA256(fileName, hash)) {
			sprintf(buffer, "fileHashSHA256 failed, size %zu", sizes[k]);
			throw(std::runtime_error(buffer));
		};
		if (hash != memoryHash<SHA256>(data, sizes[k])) {
			sprintf(buffer, "fileHashSHA256 mismatch, size %zu", sizes[k]);
			throw(std::runtime_error(buffer));
		};

		if (!Util::fileHashSHA512(fileName, hash)) {
			sprintf(buffer, "fileHashSHA512 failed, size %zu", sizes[k]);
			throw(std::runtime_error(buffer));
		};
		if (hash != memoryHash<SHA512>(data, sizes[k])) {
			sprintf(buffer, "fileHashSHA512 mismatch, size %zu", sizes[k]);
			throw(std::runtime_error(buffer));
		};
	};

	Shell::removeFile(fileName);

	if (Util::fileHashSHA256(fileName, hash) || Util::fileHashSHA512(fileName, hash)) {
		throw(std::runtime_error("file hash of missing file"));
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

	Shell::removeFile(fileName);
	return 1;
};
