// Cryptography
// Copyright (c) 2022 Grigore Stefan <g_stefan@yahoo.com>
// MIT License (MIT) <http://opensource.org/licenses/MIT>
// SPDX-FileCopyrightText: 2022 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: MIT

#ifndef XYO_CRYPTOGRAPHY_SHA256_HPP
#define XYO_CRYPTOGRAPHY_SHA256_HPP

#ifndef XYO_CRYPTOGRAPHY_DEPENDENCY_HPP
#	include <XYO/Cryptography/Dependency.hpp>
#endif

namespace XYO::Cryptography {

	class SHA256 : public Object {
			XYO_DISALLOW_COPY_ASSIGN_MOVE(SHA256);

		protected:
			XYO_CRYPTOGRAPHY_EXPORT static const uint32_t k_[];

			uint32_t h0, h1, h2, h3, h4, h5, h6, h7;

			uint32_t process[16];
			uint8_t lastData[4];
			uint64_t length;
			size_t stateM;

		public:
			XYO_CRYPTOGRAPHY_EXPORT SHA256();
			XYO_CRYPTOGRAPHY_EXPORT void processInit();
			XYO_CRYPTOGRAPHY_EXPORT void hashBlock(uint32_t *w_);
			XYO_CRYPTOGRAPHY_EXPORT void processU8(const uint8_t *toHash, size_t length);
			XYO_CRYPTOGRAPHY_EXPORT void processDone();
			XYO_CRYPTOGRAPHY_EXPORT String getHashHex();
			XYO_CRYPTOGRAPHY_EXPORT void toU8(uint8_t *buffer);
			XYO_CRYPTOGRAPHY_EXPORT void copy(const SHA256 &in);

			XYO_CRYPTOGRAPHY_EXPORT static String hash(const String &toHash);
			XYO_CRYPTOGRAPHY_EXPORT static void hashToU8(const String &toHash, uint8_t *buffer);
	};

};

#endif
