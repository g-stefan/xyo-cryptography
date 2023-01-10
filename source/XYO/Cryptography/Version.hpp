// Cryptography
// Copyright (c) 2016-2023 Grigore Stefan <g_stefan@yahoo.com>
// MIT License (MIT) <http://opensource.org/licenses/MIT>
// SPDX-FileCopyrightText: 2016-2023 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: MIT

#ifndef XYO_CRYPTOGRAPHY_VERSION_HPP
#define XYO_CRYPTOGRAPHY_VERSION_HPP

#ifndef XYO_CRYPTOGRAPHY_DEPENDENCY_HPP
#	include <XYO/Cryptography/Dependency.hpp>
#endif

namespace XYO::Cryptography::Version {

	XYO_CRYPTOGRAPHY_EXPORT const char *version();
	XYO_CRYPTOGRAPHY_EXPORT const char *build();
	XYO_CRYPTOGRAPHY_EXPORT const char *versionWithBuild();
	XYO_CRYPTOGRAPHY_EXPORT const char *datetime();

};

#endif
