// Cryptography
// Copyright (c) 2016-2024 Grigore Stefan <g_stefan@yahoo.com>
// MIT License (MIT) <http://opensource.org/licenses/MIT>
// SPDX-FileCopyrightText: 2016-2024 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: MIT

#ifndef XYO_CRYPTOGRAPHY_SHA512_HPP
#define XYO_CRYPTOGRAPHY_SHA512_HPP

#ifndef XYO_CRYPTOGRAPHY_DEPENDENCY_HPP
#	include <XYO/Cryptography/Dependency.hpp>
#endif

namespace XYO::Cryptography {

	class SHA512 : public Object {
			XYO_PLATFORM_DISALLOW_COPY_ASSIGN_MOVE(SHA512);

		protected:
			XYO_CRYPTOGRAPHY_EXPORT static const uint64_t k_[];

			uint64_t h0, h1, h2, h3, h4, h5, h6, h7;

			uint64_t process[16];
			uint8_t lastData[8];
			uint64_t length0;
			uint64_t length1;
			size_t stateM;

		public:
			XYO_CRYPTOGRAPHY_EXPORT SHA512();
			XYO_CRYPTOGRAPHY_EXPORT void processInit();
			XYO_CRYPTOGRAPHY_EXPORT void hashBlock(uint64_t *w_);
			XYO_CRYPTOGRAPHY_EXPORT void processU8(const uint8_t *toHash, size_t length);
			XYO_CRYPTOGRAPHY_EXPORT void processDone();
			XYO_CRYPTOGRAPHY_EXPORT String getHashHex();
			XYO_CRYPTOGRAPHY_EXPORT void toU8(uint8_t *buffer);
			XYO_CRYPTOGRAPHY_EXPORT void copy(const SHA512 &in);

			XYO_CRYPTOGRAPHY_EXPORT static String hash(const String &toHash);
			XYO_CRYPTOGRAPHY_EXPORT static void hashToU8(const String &toHash, uint8_t *buffer);
	};

};

#endif
