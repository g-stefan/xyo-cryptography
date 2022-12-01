// Cryptography
// Copyright (c) 2022 Grigore Stefan <g_stefan@yahoo.com>
// MIT License (MIT) <http://opensource.org/licenses/MIT>
// SPDX-FileCopyrightText: 2022 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: MIT

#include <XYO/Cryptography/SHA512.hpp>

//
// http://en.wikipedia.org/wiki/SHA-2
//

namespace XYO::Cryptography {

	const uint64_t SHA512::k_[] = {
	    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
	    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
	    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
	    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
	    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
	    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
	    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
	    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
	    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
	    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
	    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
	    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
	    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

	SHA512::SHA512() {
		processInit();
	};

	void SHA512::processInit() {
		h0 = 0x6a09e667f3bcc908;
		h1 = 0xbb67ae8584caa73b;
		h2 = 0x3c6ef372fe94f82b;
		h3 = 0xa54ff53a5f1d36f1;
		h4 = 0x510e527fade682d1;
		h5 = 0x9b05688c2b3e6c1f;
		h6 = 0x1f83d9abfb41bd6b;
		h7 = 0x5be0cd19137e2179;

		length0 = 0;
		length1 = 0;
		stateM = 0;
		lastData[0] = 0;
		lastData[1] = 0;
		lastData[2] = 0;
		lastData[3] = 0;
		lastData[4] = 0;
		lastData[5] = 0;
		lastData[6] = 0;
		lastData[7] = 0;
	};

	void SHA512::hashBlock(uint64_t *w_) {
		int k;
		uint64_t s0, s1, temp1, temp2;
		uint64_t maj, ch;
		uint64_t a, b, c, d, e, f, g, h;
		uint64_t w[80];

		for (k = 0; k < 16; ++k) {
			w[k] = w_[k];
		};

		for (k = 16; k < 80; ++k) {
			s0 = UConvert::u64RightRotate(w[k - 15], 1) ^ UConvert::u64RightRotate(w[k - 15], 8) ^ (w[k - 15] >> 7);
			s1 = UConvert::u64RightRotate(w[k - 2], 19) ^ UConvert::u64RightRotate(w[k - 2], 61) ^ (w[k - 2] >> 6);
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

		for (k = 0; k < 80; ++k) {

			s1 = UConvert::u64RightRotate(e, 14) ^ UConvert::u64RightRotate(e, 18) ^ UConvert::u64RightRotate(e, 41);
			ch = (e & f) ^ ((~e) & g);
			temp1 = h + s1 + ch + k_[k] + w[k];
			s0 = UConvert::u64RightRotate(a, 28) ^ UConvert::u64RightRotate(a, 34) ^ UConvert::u64RightRotate(a, 39);
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

	void SHA512::processU8(const uint8_t *toHash, size_t length_) {
		size_t k, z;
		size_t m = length0 % 8;
		size_t length__ = length_ & (~((size_t)(0x07)));

		if (((uint64_t)0xFFFFFFFFFFFFFFFF) - ((uint64_t)length_) >= length0) {
			length0 += ((uint64_t)length_);
		} else {
			length0 += ((uint64_t)length_);
			length1++;
		};

		if (m) {

			for (k = m, z = 0; z < length_;) {
				lastData[k] = *toHash;
				++toHash;
				++z;
				++k;
				if (k == 8) {
					break;
				};
			};
			if (k != 8) {
				return;
			};
			length_ -= z;
			process[stateM] = UConvert::u64FromU8Reversed(lastData);

			++stateM;
			if (stateM == 16) {
				hashBlock(process);
				stateM = 0;
			};
		};

		for (k = 0; k < length__; k += 8) {
			process[stateM] = UConvert::u64FromU8Reversed(toHash);
			toHash += 8;
			++stateM;
			if (stateM == 16) {
				hashBlock(process);
				stateM = 0;
			};
		};

		m = length_ % 8;
		if (m) {
			for (k = 0; k < m; ++k) {
				lastData[k] = *toHash;
				++toHash;
			};
		};
	};

	void SHA512::processDone() {
		size_t m = length0 % 128;
		uint64_t finalLength1 = (length1 << 3) | (length0 >> 61);
		uint64_t finalLength0 = length0 << 3;
		uint8_t data[8];
		memset(data, 0, sizeof(data));
		if (m < 112) {
			data[0] = 0x80;
			processU8(data, 1);
			++m;
			data[0] = 0;
			for (; m < 112; ++m) {
				processU8(data, 1);
			};
			UConvert::u64ToU8Reversed(finalLength1, data);
			processU8(data, 8);
			UConvert::u64ToU8Reversed(finalLength0, data);
			processU8(data, 8);
			return;
		};
		if (m < 128) {
			data[0] = 0x80;
			processU8(data, 1);
			++m;
			data[0] = 0;
			for (; m < 128 + 112; ++m) {
				processU8(data, 1);
			};
			UConvert::u64ToU8Reversed(finalLength1, data);
			processU8(data, 8);
			UConvert::u64ToU8Reversed(finalLength0, data);
			processU8(data, 8);
			return;
		};
		data[0] = 0x80;
		processU8(data, 1);
		++m;
		data[0] = 0;
		for (; m < 112; ++m) {
			processU8(data, 1);
		};
		UConvert::u64ToU8Reversed(finalLength1, data);
		processU8(data, 8);
		UConvert::u64ToU8Reversed(finalLength0, data);
		processU8(data, 8);
	};

	String SHA512::getHashHex() {
		StringReference *retV = TMemory<StringReference>::newMemory();
		retV->init(128);
		uint8_t result[64];
		toU8(result);
		int k;
		for (k = 0; k < 64; ++k) {
			retV->concatenateX(THex<char>::encodeLowercase((result[k] >> 4) & 0x0F));
			retV->concatenateX(THex<char>::encodeLowercase((result[k]) & 0x0F));
		};
		return retV;
	};

	String SHA512::hash(const String &toHash) {
		SHA512 hash;
		hash.processU8((uint8_t *)toHash.value(), toHash.length());
		hash.processDone();
		return hash.getHashHex();
	};

	void SHA512::hashToU8(const String &toHash, uint8_t *buffer) {
		SHA512 hash;
		hash.processU8((uint8_t *)toHash.value(), toHash.length());
		hash.processDone();
		hash.toU8(buffer);
	};

	void SHA512::toU8(uint8_t *buffer) {
		UConvert::u64ToU8Reversed(h0, buffer);
		UConvert::u64ToU8Reversed(h1, buffer + 8);
		UConvert::u64ToU8Reversed(h2, buffer + 16);
		UConvert::u64ToU8Reversed(h3, buffer + 24);
		UConvert::u64ToU8Reversed(h4, buffer + 32);
		UConvert::u64ToU8Reversed(h5, buffer + 40);
		UConvert::u64ToU8Reversed(h6, buffer + 48);
		UConvert::u64ToU8Reversed(h7, buffer + 56);
	};

	void SHA512::copy(const SHA512 &in) {
		h0 = in.h0;
		h1 = in.h1;
		h2 = in.h2;
		h3 = in.h3;
		h4 = in.h4;
		h5 = in.h5;
		h6 = in.h6;
		h7 = in.h7;

		memcpy(process, in.process, sizeof(uint64_t) * 16);
		memcpy(lastData, in.lastData, sizeof(uint8_t) * 8);

		length0 = in.length0;
		length1 = in.length1;
		stateM = in.stateM;
	};

};
