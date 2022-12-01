// Cryptography
// Copyright (c) 2022 Grigore Stefan <g_stefan@yahoo.com>
// MIT License (MIT) <http://opensource.org/licenses/MIT>
// SPDX-FileCopyrightText: 2022 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: MIT

#ifndef XYO_CRYPTOGRAPHY_COPYRIGHT_HPP
#define XYO_CRYPTOGRAPHY_COPYRIGHT_HPP

#ifndef XYO_CRYPTOGRAPHY_DEPENDENCY_HPP
#	include <XYO/Cryptography/Dependency.hpp>
#endif

namespace XYO::Cryptography::Copyright {
	XYO_CRYPTOGRAPHY_EXPORT const char *copyright();
	XYO_CRYPTOGRAPHY_EXPORT const char *publisher();
	XYO_CRYPTOGRAPHY_EXPORT const char *company();
	XYO_CRYPTOGRAPHY_EXPORT const char *contact();
	XYO_CRYPTOGRAPHY_EXPORT const char *fullCopyright();
};

#endif
