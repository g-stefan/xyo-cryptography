// Cryptography
// Copyright (c) 2016-2023 Grigore Stefan <g_stefan@yahoo.com>
// MIT License (MIT) <http://opensource.org/licenses/MIT>
// SPDX-FileCopyrightText: 2016-2023 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: MIT

#ifndef XYO_CRYPTOGRAPHY_COPYRIGHT_HPP
#define XYO_CRYPTOGRAPHY_COPYRIGHT_HPP

#ifndef XYO_CRYPTOGRAPHY_DEPENDENCY_HPP
#	include <XYO/Cryptography/Dependency.hpp>
#endif

namespace XYO::Cryptography::Copyright {
	XYO_CRYPTOGRAPHY_EXPORT std::string copyright();
	XYO_CRYPTOGRAPHY_EXPORT std::string publisher();
	XYO_CRYPTOGRAPHY_EXPORT std::string company();
	XYO_CRYPTOGRAPHY_EXPORT std::string contact();
};

#endif
