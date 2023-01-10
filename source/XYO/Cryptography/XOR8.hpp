// Cryptography
// Copyright (c) 2016-2023 Grigore Stefan <g_stefan@yahoo.com>
// MIT License (MIT) <http://opensource.org/licenses/MIT>
// SPDX-FileCopyrightText: 2016-2023 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: MIT

#ifndef XYO_CRYPTOGRAPHY_XOR8_HPP
#define XYO_CRYPTOGRAPHY_XOR8_HPP

#ifndef XYO_CRYPTOGRAPHY_DEPENDENCY_HPP
#	include <XYO/Cryptography/Dependency.hpp>
#endif

namespace XYO::Cryptography {

	XYO_CRYPTOGRAPHY_EXPORT void xor8(uint8_t *inOut, size_t inOutLn, const uint8_t *key, size_t keyLn);

};

#endif
