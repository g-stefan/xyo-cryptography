// Created by Grigore Stefan <g_stefan@yahoo.com>
// Public domain (Unlicense) <http://unlicense.org>
// SPDX-FileCopyrightText: 2016-2025 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: Unlicense

#include <XYO/Cryptography.hpp>

using namespace XYO::Cryptography;

void test() {
	String toCrypt("Hello World!");
	String password("secret");
	Buffer encrypted;
	Buffer decrypted;

	Crypt::encrypt(reinterpret_cast<const uint8_t *>(password.value()), password.length(),
	               reinterpret_cast<const uint8_t *>(toCrypt.value()), toCrypt.length(), encrypted);

	if (!Crypt::decrypt(reinterpret_cast<const uint8_t *>(password.value()), password.length(),
	                    encrypted.buffer, encrypted.length, decrypted)) {
		throw(std::runtime_error("decrypt"));
	};

	if (decrypted.toString() != toCrypt) {
		throw(std::runtime_error("decrypt check"));
	};

	if (!Crypt::checkIntegrity(reinterpret_cast<const uint8_t *>(password.value()), password.length(),
	                           encrypted.buffer, encrypted.length,
	                           &encrypted.buffer[64])) {
		throw(std::runtime_error("check integrity"));
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
