// Cryptography
// Copyright (c) 2016-2025 Grigore Stefan <g_stefan@yahoo.com>
// MIT License (MIT) <http://opensource.org/licenses/MIT>
// SPDX-FileCopyrightText: 2016-2025 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: MIT

#ifndef XYO_CRYPTOGRAPHY_CRYPT_HPP
#define XYO_CRYPTOGRAPHY_CRYPT_HPP

#ifndef XYO_CRYPTOGRAPHY_DEPENDENCY_HPP
#	include <XYO/Cryptography/Dependency.hpp>
#endif

namespace XYO::Cryptography::Crypt {

	XYO_CRYPTOGRAPHY_EXPORT void encrypt(const uint8_t *password, size_t passwordSize, const uint8_t *data, size_t dataSize, Buffer &output);
	XYO_CRYPTOGRAPHY_EXPORT bool decrypt(const uint8_t *password, size_t passwordSize, const uint8_t *data, size_t dataSize, Buffer &output);
	XYO_CRYPTOGRAPHY_EXPORT bool encryptFile(const uint8_t *password, size_t passwordSize, const char *fileNameIn, const char *fileNameOut);
	XYO_CRYPTOGRAPHY_EXPORT bool decryptFile(const uint8_t *password, size_t passwordSize, const char *fileNameIn, const char *fileNameOut);
	XYO_CRYPTOGRAPHY_EXPORT bool checkIntegrity(const uint8_t *password, size_t passwordSize, const uint8_t *data, size_t dataSize_, const uint8_t *integrity);

};

#endif
