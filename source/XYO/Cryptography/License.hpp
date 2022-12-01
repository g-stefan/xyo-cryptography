// Cryptography
// Copyright (c) 2022 Grigore Stefan <g_stefan@yahoo.com>
// MIT License (MIT) <http://opensource.org/licenses/MIT>
// SPDX-FileCopyrightText: 2022 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: MIT

#ifndef XYO_CRYPTOGRAPHY_LICENSE_HPP
#define XYO_CRYPTOGRAPHY_LICENSE_HPP

#ifndef XYO_CRYPTOGRAPHY_DEPENDENCY_HPP
#	include <XYO/Cryptography/Dependency.hpp>
#endif

namespace XYO::Cryptography::License {

	XYO_CRYPTOGRAPHY_EXPORT const char *license();
	XYO_CRYPTOGRAPHY_EXPORT const char *shortLicense();

};

#endif
