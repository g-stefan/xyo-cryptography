// Created by Grigore Stefan <g_stefan@yahoo.com>
// Public domain (Unlicense) <http://unlicense.org>
// SPDX-FileCopyrightText: 2016-2023 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: Unlicense

#include <XYO/Cryptography.hpp>

using namespace XYO::Cryptography;

static const char *checkHash[][2] = {
    {"", "d41d8cd98f00b204e9800998ecf8427e"},
    {"0", "cfcd208495d565ef66e7dff9f98764da"},
    {"01", "96a3be3cf272e017046d1b2674a52bd3"},
    {"012", "d2490f048dc3b77a457e3e450ab4eb38"},
    {"0123", "eb62f6b9306db575c2d596b1279627a4"},
    {"The quick brown fox jumps over the lazy dog", "9e107d9d372bb6826bd81d3542a419d6"},
    {"The quick brown fox jumps over the lazy dog.", "e4d909c290d0fb1ca068ffaddf22cbd0"},
    {"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789AB", "40e82857e8d2a080e2a31a166f1ba490"},
    {"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", "e889d82dd111d6315d7b1edce2b1b30f"},
    {"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234", "1f413faa1298d5400bbd48eef8b650c1"},
    {nullptr, nullptr}};

void test() {
	int k;
	for (k = 0; checkHash[k][0] != nullptr; ++k) {
		String hash = MD5::hash(checkHash[k][0]);
		if (hash != checkHash[k][1]) {
			char buffer[1024];
			sprintf(buffer, "invalid MD5 %s should be %s from \"%s\"\n", hash.value(), checkHash[k][1], checkHash[k][0]);
			throw(std::runtime_error(buffer));
		};
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
