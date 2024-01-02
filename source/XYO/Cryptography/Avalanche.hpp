// Cryptography
// Copyright (c) 2016-2024 Grigore Stefan <g_stefan@yahoo.com>
// MIT License (MIT) <http://opensource.org/licenses/MIT>
// SPDX-FileCopyrightText: 2016-2024 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: MIT

#ifndef XYO_CRYPTOGRAPHY_AVALANCHE_HPP
#define XYO_CRYPTOGRAPHY_AVALANCHE_HPP

#ifndef XYO_CRYPTOGRAPHY_DEPENDENCY_HPP
#	include <XYO/Cryptography/Dependency.hpp>
#endif

namespace XYO::Cryptography::Avalanche {

	XYO_CRYPTOGRAPHY_EXPORT void encode(uint8_t *data, size_t dataLn);
	XYO_CRYPTOGRAPHY_EXPORT void decode(uint8_t *data, size_t dataLn);

};

#endif
