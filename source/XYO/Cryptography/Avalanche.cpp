// Cryptography
// Copyright (c) 2022 Grigore Stefan <g_stefan@yahoo.com>
// MIT License (MIT) <http://opensource.org/licenses/MIT>
// SPDX-FileCopyrightText: 2022 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: MIT

#include <XYO/Cryptography/Avalanche.hpp>

namespace XYO::Cryptography::Avalanche {

	void encode(uint8_t *data, size_t dataLn) {
		if (dataLn == 0) {
			return;
		};
		while (dataLn > 0) {
			if (dataLn - 1 > 0) {
				*(data + 1) ^= *data;
			};
			--dataLn;
			++data;
		};
	};

	void decode(uint8_t *data, size_t dataLn) {
		if (dataLn == 0) {
			return;
		};
		uint8_t last_ = *data;
		uint8_t next_;
		while (dataLn > 0) {
			if (dataLn - 1 > 0) {
				next_ = *(data + 1);
				*(data + 1) ^= last_;
				last_ = next_;
			};
			--dataLn;
			++data;
		};
	};

};
