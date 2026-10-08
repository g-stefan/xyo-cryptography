// Cryptography
// Copyright (c) 2016-2026 Grigore Stefan <g_stefan@yahoo.com>
// MIT License (MIT) <http://opensource.org/licenses/MIT>
// SPDX-FileCopyrightText: 2016-2026 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: MIT

#ifndef XYO_CRYPTOGRAPHY_SYSTEMRANDOM_HPP
#define XYO_CRYPTOGRAPHY_SYSTEMRANDOM_HPP

#ifndef XYO_CRYPTOGRAPHY_DEPENDENCY_HPP
#	include <XYO/Cryptography/Dependency.hpp>
#endif

namespace XYO::Cryptography::SystemRandom {

	// Random bytes from the operating system generator,
	// BCryptGenRandom on Windows, getrandom or /dev/urandom on Linux.
	// Returns false if no source works, the buffer content is then undefined.
	XYO_CRYPTOGRAPHY_EXPORT bool generate(uint8_t *buffer, size_t length);

};

#endif
