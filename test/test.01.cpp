// Created by Grigore Stefan <g_stefan@yahoo.com>
// Public domain (Unlicense) <http://unlicense.org>
// SPDX-FileCopyrightText: 2016-2024 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: Unlicense

#include <XYO/Cryptography.hpp>

using namespace XYO::Cryptography;

static const char *checkHash[][2] = {
    {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    {"0", "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9"},
    {"01", "938db8c9f82c8cb58d3f3ef4fd250036a48d26a712753d2fde5abd03a85cabf4"},
    {"012", "bf6aaaab7c143ca12ae448c69fb72bb4cf1b29154b9086a927a0a91ae334cdf7"},
    {"0123", "1be2e452b46d7a0d9656bbb1f768e8248eba1b75baed65f5d99eafa948899a6a"},
    {"The quick brown fox jumps over the lazy dog", "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"},
    {"The quick brown fox jumps over the lazy dog.", "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c"},
    {"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789AB", "ea023a6b36a9320dee5b927776ce7ef6ee217998207467ff1f2c104e700fc877"},
    {"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", "0ea37c243f60974b0d54c6b2d76cece3f4c742492cce48eaf81f357931d6d69e"},
    {"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234", "8e887b6cb5a7e23988c68442b56424d31c3db2ff233b8eab37dccb055b7901e3"},
    {nullptr, nullptr}};

void test() {
	int k;
	for (k = 0; checkHash[k][0] != nullptr; ++k) {
		String hash = SHA256::hash(checkHash[k][0]);
		if (hash != checkHash[k][1]) {
			char buffer[1024];
			sprintf(buffer, "invalid SHA256 %s should be %s from \"%s\"\n", hash.value(), checkHash[k][1], checkHash[k][0]);
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
