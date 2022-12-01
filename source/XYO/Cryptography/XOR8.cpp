// Cryptography
// Copyright (c) 2022 Grigore Stefan <g_stefan@yahoo.com>
// MIT License (MIT) <http://opensource.org/licenses/MIT>
// SPDX-FileCopyrightText: 2022 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: MIT

#include <XYO/Cryptography/XOR8.hpp>

namespace XYO::Cryptography {

	void xor8(uint8_t *inOut, size_t inOutLn, const uint8_t *key, size_t keyLn) {
		while ((inOutLn > 0) && (keyLn > 0)) {
			*inOut ^= *key;
			--inOutLn;
			--keyLn;
			++inOut;
			++key;
		};
	};

};
