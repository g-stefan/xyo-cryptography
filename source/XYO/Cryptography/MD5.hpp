// Cryptography
// Copyright (c) 2016-2024 Grigore Stefan <g_stefan@yahoo.com>
// MIT License (MIT) <http://opensource.org/licenses/MIT>
// SPDX-FileCopyrightText: 2016-2024 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: MIT

#ifndef XYO_CRYPTOGRAPHY_MD5_HPP
#define XYO_CRYPTOGRAPHY_MD5_HPP

#ifndef XYO_CRYPTOGRAPHY_DEPENDENCY_HPP
#	include <XYO/Cryptography/Dependency.hpp>
#endif

namespace XYO::Cryptography {

	class MD5 : public Object {
			XYO_DISALLOW_COPY_ASSIGN_MOVE(MD5);

		protected:
			XYO_CRYPTOGRAPHY_EXPORT static const uint16_t r[];
			XYO_CRYPTOGRAPHY_EXPORT static const uint32_t k[];

			uint32_t h0;
			uint32_t h1;
			uint32_t h2;
			uint32_t h3;

			uint32_t process[16];
			uint8_t lastData[4];
			uint64_t length;
			size_t stateM;

		public:
			XYO_CRYPTOGRAPHY_EXPORT MD5();
			XYO_CRYPTOGRAPHY_EXPORT void processInit();
			XYO_CRYPTOGRAPHY_EXPORT void hashBlock(uint32_t *w);
			XYO_CRYPTOGRAPHY_EXPORT void processU8(const uint8_t *toHash, size_t length);
			XYO_CRYPTOGRAPHY_EXPORT void processDone();
			XYO_CRYPTOGRAPHY_EXPORT String getHashHex();
			XYO_CRYPTOGRAPHY_EXPORT void toU8(uint8_t *buffer);
			XYO_CRYPTOGRAPHY_EXPORT void copy(const MD5 &in);

			XYO_CRYPTOGRAPHY_EXPORT static String hash(const String &toHash);
			XYO_CRYPTOGRAPHY_EXPORT static void hashToU8(const String &toHash, uint8_t *buffer);
	};

};

#endif
