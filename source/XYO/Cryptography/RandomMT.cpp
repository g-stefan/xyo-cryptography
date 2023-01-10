// Cryptography
// Copyright (c) 2016-2023 Grigore Stefan <g_stefan@yahoo.com>
// MIT License (MIT) <http://opensource.org/licenses/MIT>
// SPDX-FileCopyrightText: 2016-2023 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: MIT

#include <time.h>
#include <XYO/Cryptography/RandomMT.hpp>

//
// http://en.wikipedia.org/wiki/Mersenne_twister
//

namespace XYO::Cryptography {

	RandomMT::RandomMT() {
		seed(static_cast<uint32_t>(time(nullptr)));
	};

	void RandomMT::seed(uint32_t seed_) {
		int i;
		if (seed_ == 0) {
			seed_ = static_cast<uint32_t>(time(nullptr));
		};
		mt[0] = seed_;
		for (i = 1; i < 623; ++i) {
			mt[i] = (1812433253UL * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i);
		};
		index = 0;
		value = seed_;
	};

	uint32_t RandomMT::nextRandom() {
		uint32_t y;
		if (index == 0) {
			int i;
			for (i = 1; i < 623; ++i) {
				y = (mt[i] & 0x80000000UL) + (mt[(i + 1) % 624] & 0x7fffffffUL);
				mt[i] = mt[(i + 397) % 624] ^ (y >> 1);
				if (y & 0x00000001UL) {
					mt[i] = mt[i] ^ (2567483615UL);
				};
			};
		};

		y = mt[index];
		y = y ^ (y >> 11);
		y = y ^ ((y << 7) & 2636928640UL);
		y = y ^ ((y << 15) & 4022730752UL);
		y = y ^ (y >> 18);

		index = (index + 1) % 624;
		value = y;
		return y;
	};

	uint32_t RandomMT::getValue() {
		return value;
	};

	void RandomMT::copy(RandomMT &value_) {
		index = value_.index;
		value = value_.value;
		memcpy(mt, value_.mt, 624 * sizeof(uint32_t));
	};

};
