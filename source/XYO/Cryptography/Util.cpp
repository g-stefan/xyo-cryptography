// Cryptography
// Copyright (c) 2016-2025 Grigore Stefan <g_stefan@yahoo.com>
// MIT License (MIT) <http://opensource.org/licenses/MIT>
// SPDX-FileCopyrightText: 2016-2025 Grigore Stefan <g_stefan@yahoo.com>
// SPDX-License-Identifier: MIT

#include <XYO/Cryptography/Util.hpp>
#include <XYO/Cryptography/SHA256.hpp>
#include <XYO/Cryptography/SHA512.hpp>

namespace XYO::Cryptography::Util {

	bool fileHashSHA256(const char *fileName, String &hash) {
		File fileIn;
		if (fileIn.openRead(fileName)) {
			size_t readLn;
			SHA256 hashFile;
			hashFile.processInit();
			uint8_t buffer[32768];
			for (;;) {
				readLn = fileIn.read(buffer, 32768);
				if (readLn > 0) {
					hashFile.processU8(buffer, readLn);
				};
				if (readLn < 32768) {
					break;
				};
			};
			hashFile.processDone();
			hash = hashFile.getHashHex();
			fileIn.close();
			return true;
		};
		return false;
	};

	bool fileHashSHA512(const char *fileName, String &hash) {
		File fileIn;
		if (fileIn.openRead(fileName)) {
			size_t readLn;
			SHA512 hashFile;
			hashFile.processInit();
			uint8_t buffer[32768];
			for (;;) {
				readLn = fileIn.read(buffer, 32768);
				if (readLn > 0) {
					hashFile.processU8(buffer, readLn);
				};
				if (readLn < 32768) {
					break;
				};
			};
			hashFile.processDone();
			hash = hashFile.getHashHex();
			fileIn.close();
			return true;
		};
		return false;
	};

};
