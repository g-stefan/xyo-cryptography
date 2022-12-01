// Created by Grigore Stefan <g_stefan@yahoo.com>
// Public domain (Unlicense) <http://unlicense.org>
// SPDX-FileCopyrightText: 2022 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: Unlicense

#include <XYO/Cryptography.hpp>

using namespace XYO::Cryptography;

static const char *checkHash[][2] = {
    {"", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
    {"abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
    {"0", "31bca02094eb78126a517b206a88c73cfa9ec6f704c7030d18212cace820f025f00bf0ea68dbf3f3a5436ca63b53bf7bf80ad8d5de7d8359d0b7fed9dbc3ab99"},
    {"01", "7b3e2f9860391685c2ff6785ab60541bb0db11a20b7e511bf020f4b3073053cc36b647d82f520c5a1c323e853f4bb110fce8210ba409fa42069ab4bf0b0d39e1"},
    {"012", "170c248082fd9075ae4705e182f6f6f2ccafdc431c92a1fbd0918d070a568e7eb5fe2c219baa0bfdcd52b9d60d09c16e4f8275bdfd65f3730eb7e72c9a331e75"},
    {"0123", "26e5556d35bebab660c17eaf2ffebb823ddfb4b009a6e1f687e95fdf40ee637040fe258bb737d537c5d04d2558f2d2e802b2ef492944330f0b8e4bb17222e1d5"},
    {"The quick brown fox jumps over the lazy dog", "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"},
    {"The quick brown fox jumps over the lazy dog.", "91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bbc6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed"},
    {"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789AB", "4e7cc455d4893b9ed3d9d0d8228530022beb2da35a0e410763087fe3ce0d6428eae3696e8652d2f0455fc0ae2516c3f6872d7a49638d9a3c0975e80062ba3114"},
    {"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", "3950accdfef74620714278765bbdce04d457904b7cea8631396cba6d8bcefce0308fc47cfb885bc89ebdf4ffa6f98fc85105547cbddf5657b6adbddda38cb9b5"},
    {"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234", "82c6bcbb82d1b27190f931b40b9a59dad9e851bba2d9b50e639b5e3d2afb073d447124f707958950e3fb35bd8fc42067af03c63c6741fb494fd8732d14caab20"},
    {nullptr, nullptr}};

void test() {
	int k;
	for (k = 0; checkHash[k][0] != nullptr; ++k) {
		String hash = SHA512::hash(checkHash[k][0]);
		if (hash != checkHash[k][1]) {
			char buffer[1024];
			sprintf(buffer, "* Error: invalid SHA512 %s should be %s from \"%s\"\n", hash.value(), checkHash[k][1], checkHash[k][0]);
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
