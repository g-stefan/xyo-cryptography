// Cryptography
// Copyright (c) 2016-2025 Grigore Stefan <g_stefan@yahoo.com>
// MIT License (MIT) <http://opensource.org/licenses/MIT>
// SPDX-FileCopyrightText: 2016-2025 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: MIT

#include <XYO/Cryptography/MD5.hpp>

//
// http://en.wikipedia.org/wiki/MD5
//

namespace XYO::Cryptography {

	const uint16_t MD5::r[] = {
	    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

	const uint32_t MD5::k[] = {
	    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

	MD5::MD5() {
		processInit();
	};

	void MD5::processInit() {
		h0 = 0x67452301;
		h1 = 0xefcdab89;
		h2 = 0x98badcfe;
		h3 = 0x10325476;
		length = 0;
		stateM = 0;
		lastData[0] = 0;
		lastData[1] = 0;
		lastData[2] = 0;
		lastData[3] = 0;
	};

	void MD5::hashBlock(uint32_t *w) {
		uint32_t a;
		uint32_t b;
		uint32_t c;
		uint32_t d;

		uint32_t f;
		uint32_t temp;

		int i;
		int g;

		a = h0;
		b = h1;
		c = h2;
		d = h3;

		f = 0;
		g = 0;

		for (i = 0; i < 64; ++i) {
			if (i < 16) {
				f = (b & c) | ((~b) & d);
				g = i;
			};
			if (i >= 16 && i < 32) {
				f = (d & b) | ((~d) & c);
				g = (5 * i + 1) % 16;
			};
			if (i >= 32 && i < 48) {
				f = b ^ c ^ d;
				g = (3 * i + 5) % 16;
			};
			if (i >= 48 && i < 64) {
				f = c ^ (b | (~d));
				g = (7 * i) % 16;
			};
			temp = d;
			d = c;
			c = b;

			b = b + UConvert::u32LeftRotate(a + f + k[i] + w[g], r[i]);
			a = temp;
		};

		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
	};

	void MD5::processU8(const uint8_t *toHash, size_t length_) {
		size_t k, z;
		size_t m = length % 4;
		size_t length__ = length_ & (~((size_t)(0x03)));

		length += length_;

		if (m) {

			for (k = m, z = 0; z < length_;) {
				lastData[k] = *toHash;
				++toHash;
				++z;
				++k;
				if (k == 4) {
					break;
				};
			};
			if (k != 4) {
				return;
			};
			length_ -= z;
			process[stateM] = UConvert::u32FromU8(lastData);

			++stateM;
			if (stateM == 16) {
				hashBlock(process);
				stateM = 0;
			};
		};

		for (k = 0; k < length__; k += 4) {
			process[stateM] = UConvert::u32FromU8(toHash);
			toHash += 4;
			++stateM;
			if (stateM == 16) {
				hashBlock(process);
				stateM = 0;
			};
		};

		m = length_ % 4;
		if (m) {
			for (k = 0; k < m; ++k) {
				lastData[k] = *toHash;
				++toHash;
			};
		};
	};

	void MD5::processDone() {
		size_t m = length % 64;
		uint64_t finalLength = length * 8;
		uint8_t data[8];
		memset(data, 0, sizeof(data));
		if (m < 56) {
			data[0] = 0x80;
			processU8(data, 1);
			++m;
			data[0] = 0;
			for (; m < 56; ++m) {
				processU8(data, 1);
			};
			UConvert::u64ToU8(finalLength, data);
			processU8(data, 8);
			return;
		};
		if (m < 63) {
			data[0] = 0x80;
			processU8(data, 1);
			++m;
			data[0] = 0;
			for (; m < 64 + 56; ++m) {
				processU8(data, 1);
			};
			UConvert::u64ToU8(finalLength, data);
			processU8(data, 8);
			return;
		};
		data[0] = 0x80;
		processU8(data, 1);
		++m;
		data[0] = 0;
		for (; m < 56; ++m) {
			processU8(data, 1);
		};
		UConvert::u64ToU8(finalLength, data);
		processU8(data, 8);
	};

	String MD5::getHashHex() {
		StringReference *retV = TMemory<StringReference>::newMemory();
		retV->init(32);
		uint8_t result[16];
		toU8(result);
		int k;
		for (k = 0; k < 16; ++k) {
			retV->concatenateX(THex<char>::encodeLowercase((result[k] >> 4) & 0x0F));
			retV->concatenateX(THex<char>::encodeLowercase((result[k]) & 0x0F));
		};
		return retV;
	};

	String MD5::hash(const String &toHash) {
		MD5 hash;
		hash.processU8((uint8_t *)toHash.value(), toHash.length());
		hash.processDone();
		return hash.getHashHex();
	};

	void MD5::hashToU8(const String &toHash, uint8_t *buffer) {
		MD5 hash;
		hash.processU8((uint8_t *)toHash.value(), toHash.length());
		hash.processDone();
		hash.toU8(buffer);
	};

	void MD5::toU8(uint8_t *buffer) {
		UConvert::u32ToU8(h0, buffer);
		UConvert::u32ToU8(h1, buffer + 4);
		UConvert::u32ToU8(h2, buffer + 8);
		UConvert::u32ToU8(h3, buffer + 12);
	};

	void MD5::copy(const MD5 &in) {
		h0 = in.h0;
		h1 = in.h1;
		h2 = in.h2;
		h3 = in.h3;

		memcpy(process, in.process, sizeof(uint32_t) * 16);
		memcpy(lastData, in.lastData, sizeof(uint8_t) * 4);

		length = in.length;
		stateM = in.stateM;
	};

};
