// Cryptography
// Copyright (c) 2016-2026 Grigore Stefan <g_stefan@yahoo.com>
// MIT License (MIT) <http://opensource.org/licenses/MIT>
// SPDX-FileCopyrightText: 2016-2026 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: MIT

#include <XYO/Cryptography/SystemRandom.hpp>

#ifdef XYO_PLATFORM_OS_LINUX

#	include <errno.h>
#	include <fcntl.h>
#	include <unistd.h>
#	include <sys/syscall.h>

namespace XYO::Cryptography::SystemRandom {

	// getrandom through syscall, works without the glibc wrapper (glibc < 2.25),
	// fails with ENOSYS on kernels older than 3.17
	static bool generateGetRandom(uint8_t *buffer, size_t length) {
#	ifdef SYS_getrandom
		long ln;
		while (length > 0) {
			ln = syscall(SYS_getrandom, buffer, length, 0);
			if (ln < 0) {
				if (errno == EINTR) {
					continue;
				};
				return false;
			};
			buffer += ln;
			length -= static_cast<size_t>(ln);
		};
		return true;
#	else
		return false;
#	endif
	};

	static bool generateDevURandom(uint8_t *buffer, size_t length) {
		int fd;
		do {
			fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
		} while ((fd < 0) && (errno == EINTR));
		if (fd < 0) {
			return false;
		};
		ssize_t ln;
		while (length > 0) {
			ln = ::read(fd, buffer, length);
			if (ln < 0) {
				if (errno == EINTR) {
					continue;
				};
				break;
			};
			if (ln == 0) {
				break;
			};
			buffer += ln;
			length -= static_cast<size_t>(ln);
		};
		::close(fd);
		return (length == 0);
	};

	bool generate(uint8_t *buffer, size_t length) {
		if (generateGetRandom(buffer, length)) {
			return true;
		};
		return generateDevURandom(buffer, length);
	};

};

#endif
