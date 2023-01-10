// Cryptography
// Copyright (c) 2016-2023 Grigore Stefan <g_stefan@yahoo.com>
// MIT License (MIT) <http://opensource.org/licenses/MIT>
// SPDX-FileCopyrightText: 2016-2023 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: MIT

#ifndef XYO_CRYPTOGRAPHY_UTIL_HPP
#define XYO_CRYPTOGRAPHY_UTIL_HPP

#ifndef XYO_CRYPTOGRAPHY_DEPENDENCY_HPP
#	include <XYO/Cryptography/Dependency.hpp>
#endif

namespace XYO::Cryptography::Util {

	XYO_CRYPTOGRAPHY_EXPORT bool fileHashSHA256(const char *fileName, String &hash);
	XYO_CRYPTOGRAPHY_EXPORT bool fileHashSHA512(const char *fileName, String &hash);

};

#endif
