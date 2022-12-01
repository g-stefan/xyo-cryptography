// Cryptography
// Copyright (c) 2022 Grigore Stefan <g_stefan@yahoo.com>
// MIT License (MIT) <http://opensource.org/licenses/MIT>
// SPDX-FileCopyrightText: 2022 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: MIT

#ifndef XYO_CRYPTOGRAPHY_DEPENDENCY_HPP
#define XYO_CRYPTOGRAPHY_DEPENDENCY_HPP

#ifndef XYO_SYSTEM_HPP
#	include <XYO/System.hpp>
#endif

// -- Export

#ifdef XYO_CRYPTOGRAPHY_INTERNAL
#	define XYO_CRYPTOGRAPHY_EXPORT XYO_LIBRARY_EXPORT
#else
#	define XYO_CRYPTOGRAPHY_EXPORT XYO_LIBRARY_IMPORT
#endif

// --

namespace XYO::Cryptography {
	using namespace XYO::ManagedMemory;
	using namespace XYO::DataStructures;
	using namespace XYO::Encoding;
	using namespace XYO::Multithreading;
	using namespace XYO::System;
};

#endif
