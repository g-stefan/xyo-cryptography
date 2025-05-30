// Cryptography
// Copyright (c) 2016-2025 Grigore Stefan <g_stefan@yahoo.com>
// MIT License (MIT) <http://opensource.org/licenses/MIT>
// SPDX-FileCopyrightText: 2016-2025 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: MIT

#include <XYO/Cryptography/SHA256.hpp>

//
// http://en.wikipedia.org/wiki/SHA-2
//

namespace XYO::Cryptography {

	const uint32_t SHA256::k_[] = {
	    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

	SHA256::SHA256() {
		processInit();
	};

	void SHA256::processInit() {
		h0 = 0x6a09e667;
		h1 = 0xbb67ae85;
		h2 = 0x3c6ef372;
		h3 = 0xa54ff53a;
		h4 = 0x510e527f;
		h5 = 0x9b05688c;
		h6 = 0x1f83d9ab;
		h7 = 0x5be0cd19;

		length = 0;
		stateM = 0;
		lastData[0] = 0;
		lastData[1] = 0;
		lastData[2] = 0;
		lastData[3] = 0;
	};

	void SHA256::hashBlock(uint32_t *w_) {
		int k;
		uint32_t s0, s1, temp1, temp2;
		uint32_t maj, ch;
		uint32_t a, b, c, d, e, f, g, h;
		uint32_t w[64];

		for (k = 0; k < 16; ++k) {
			w[k] = w_[k];
		};

		for (k = 16; k < 64; ++k) {
			s0 = UConvert::u32RightRotate(w[k - 15], 7) ^ UConvert::u32RightRotate(w[k - 15], 18) ^ (w[k - 15] >> 3);
			s1 = UConvert::u32RightRotate(w[k - 2], 17) ^ UConvert::u32RightRotate(w[k - 2], 19) ^ (w[k - 2] >> 10);
			w[k] = w[k - 16] + s0 + w[k - 7] + s1;
		};

		a = h0;
		b = h1;
		c = h2;
		d = h3;
		e = h4;
		f = h5;
		g = h6;
		h = h7;

		for (k = 0; k < 64; ++k) {

			s1 = UConvert::u32RightRotate(e, 6) ^ UConvert::u32RightRotate(e, 11) ^ UConvert::u32RightRotate(e, 25);
			ch = (e & f) ^ ((~e) & g);
			temp1 = h + s1 + ch + k_[k] + w[k];
			s0 = UConvert::u32RightRotate(a, 2) ^ UConvert::u32RightRotate(a, 13) ^ UConvert::u32RightRotate(a, 22);
			maj = (a & b) ^ (a & c) ^ (b & c);
			temp2 = s0 + maj;
			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		};

		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
		h4 += e;
		h5 += f;
		h6 += g;
		h7 += h;
	};

	void SHA256::processU8(const uint8_t *toHash, size_t length_) {
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
			process[stateM] = UConvert::u32FromU8Reversed(lastData);

			++stateM;
			if (stateM == 16) {
				hashBlock(process);
				stateM = 0;
			};
		};

		for (k = 0; k < length__; k += 4) {
			process[stateM] = UConvert::u32FromU8Reversed(toHash);
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

	void SHA256::processDone() {
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
			UConvert::u64ToU8Reversed(finalLength, data);
			processU8(data, 8);
			return;
		};
		if (m < 64) {
			data[0] = 0x80;
			processU8(data, 1);
			++m;
			data[0] = 0;
			for (; m < 64 + 56; ++m) {
				processU8(data, 1);
			};
			UConvert::u64ToU8Reversed(finalLength, data);
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
		UConvert::u64ToU8Reversed(finalLength, data);
		processU8(data, 8);
	};

	String SHA256::getHashHex() {
		StringReference *retV = TMemory<StringReference>::newMemory();
		retV->init(64);
		uint8_t result[32];
		toU8(result);
		int k;
		for (k = 0; k < 32; ++k) {
			retV->concatenateX(THex<char>::encodeLowercase((result[k] >> 4) & 0x0F));
			retV->concatenateX(THex<char>::encodeLowercase((result[k]) & 0x0F));
		};
		return retV;
	};

	String SHA256::hash(const String &toHash) {
		SHA256 hash;
		hash.processU8((uint8_t *)toHash.value(), toHash.length());
		hash.processDone();
		return hash.getHashHex();
	};

	void SHA256::hashToU8(const String &toHash, uint8_t *buffer) {
		SHA256 hash;
		hash.processU8((uint8_t *)toHash.value(), toHash.length());
		hash.processDone();
		hash.toU8(buffer);
	};

	void SHA256::toU8(uint8_t *buffer) {
		UConvert::u32ToU8Reversed(h0, buffer);
		UConvert::u32ToU8Reversed(h1, buffer + 4);
		UConvert::u32ToU8Reversed(h2, buffer + 8);
		UConvert::u32ToU8Reversed(h3, buffer + 12);
		UConvert::u32ToU8Reversed(h4, buffer + 16);
		UConvert::u32ToU8Reversed(h5, buffer + 20);
		UConvert::u32ToU8Reversed(h6, buffer + 24);
		UConvert::u32ToU8Reversed(h7, buffer + 28);
	};

	void SHA256::copy(const SHA256 &in) {
		h0 = in.h0;
		h1 = in.h1;
		h2 = in.h2;
		h3 = in.h3;
		h4 = in.h4;
		h5 = in.h5;
		h6 = in.h6;
		h7 = in.h7;

		memcpy(process, in.process, sizeof(uint32_t) * 16);
		memcpy(lastData, in.lastData, sizeof(uint8_t) * 4);

		length = in.length;
		stateM = in.stateM;
	};

};
