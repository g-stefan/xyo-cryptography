// Cryptography
// Copyright (c) 2016-2026 Grigore Stefan <g_stefan@yahoo.com>
// MIT License (MIT) <http://opensource.org/licenses/MIT>
// SPDX-FileCopyrightText: 2016-2026 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: MIT

#include <XYO/Cryptography/SystemRandom.hpp>

#ifdef XYO_PLATFORM_OS_WINDOWS

#	define WIN32_LEAN_AND_MEAN
#	include <windows.h>

namespace XYO::Cryptography::SystemRandom {

	// BCryptGenRandom is loaded at run time from System32, the build does not need bcrypt.lib
	typedef LONG(WINAPI *BCryptGenRandomProc)(void *hAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags);

	// BCRYPT_USE_SYSTEM_PREFERRED_RNG
	static const ULONG useSystemPreferredRNG = 0x00000002;

	bool generate(uint8_t *buffer, size_t length) {
		HMODULE hModule = LoadLibraryExW(L"bcrypt.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
		if (hModule == nullptr) {
			return false;
		};
		bool retV = false;
		BCryptGenRandomProc bCryptGenRandom = reinterpret_cast<BCryptGenRandomProc>(reinterpret_cast<void *>(GetProcAddress(hModule, "BCryptGenRandom")));
		if (bCryptGenRandom != nullptr) {
			retV = true;
			ULONG ln;
			while (length > 0) {
				ln = (length > 0x10000000) ? 0x10000000 : static_cast<ULONG>(length);
				if (bCryptGenRandom(nullptr, buffer, ln, useSystemPreferredRNG) != 0) {
					retV = false;
					break;
				};
				buffer += ln;
				length -= ln;
			};
		};
		FreeLibrary(hModule);
		return retV;
	};

};

#endif
